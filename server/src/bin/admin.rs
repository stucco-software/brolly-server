//! `brolly-admin` — the operational commands there was previously no way to run.
//!
//! Minting an invite meant hand-writing a SHA-256 into Postgres, and a deferred
//! PLC registration had a queue with nothing to drain it. Both are things an
//! operator needs on day one, and neither is worth a web surface.
//!
//! Printing is the entire point of a CLI, so the workspace's `print_stdout`
//! deny is lifted here and nowhere else. It exists because a *library* that
//! prints has no way to be quiet; a binary whose output is its product does not
//! have that problem.
#![allow(clippy::print_stdout, clippy::print_stderr)]

use std::process::ExitCode;

const USAGE: &str = "\
brolly-admin — operational commands

USAGE:
    brolly-admin invite [--uses N] [--expires-days N] [--admin]
    brolly-admin promote <username>
    brolly-admin demote <username>
    brolly-admin plc-retry [--dry-run]
    brolly-admin blob-sweep [--apply]
    brolly-admin whoami <username>

COMMANDS:
    invite       Mint an invite code and print it. The code is shown once;
                 only its hash is stored. --admin makes the account it
                 creates an admin, which is how an instance is handed over
                 without also handing over the database password.
    promote      Make a member an admin.
    demote      Make an admin an ordinary member. Refuses the last one.
    plc-retry    Submit PLC operations the directory has not accepted yet.
                 Safe to re-run — already-submitted operations are skipped.
    blob-sweep   Report every pod blob no resource record names, and remove
                 it with --apply (ADR 0013's promised orphan sweep; spec 4,
                 H7). Read-only without it. Runs with the server STOPPED:
                 a running server holds the stores' locks.
    whoami       Print what a member's identity resolves to.

ENVIRONMENT:
    DATABASE_URL          required
    BROLLY_BASE_DOMAIN    defaults to brolly.test
    BROLLY_DATA_DIR       blob-sweep only; defaults to data, as the server does
";

#[tokio::main]
async fn main() -> ExitCode {
    // `plc-retry` builds a reqwest client, and with `rustls-no-provider` that
    // panics until a provider is installed. First, so no command can get ahead of it.
    brolly_server::tls::install_crypto_provider();

    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(command) = args.first().map(String::as_str) else {
        eprintln!("{USAGE}");
        return ExitCode::FAILURE;
    };

    // Help before the database. Connecting first meant `--help` failed with a
    // pool timeout on a machine with no database running, which is exactly the
    // machine most likely to be asking for help.
    if matches!(command, "-h" | "--help" | "help") {
        println!("{USAGE}");
        return ExitCode::SUCCESS;
    }

    let database_url = match std::env::var("DATABASE_URL") {
        Ok(url) => url,
        Err(_) => {
            eprintln!("DATABASE_URL is not set");
            return ExitCode::FAILURE;
        }
    };
    let pool = match sqlx::PgPool::connect(&database_url).await {
        Ok(pool) => pool,
        Err(e) => {
            eprintln!("could not connect to the database: {e}");
            eprintln!("DATABASE_URL={database_url}");
            eprintln!("is the stack up? `docker compose up -d postgres`");
            return ExitCode::FAILURE;
        }
    };

    let base_domain =
        std::env::var("BROLLY_BASE_DOMAIN").unwrap_or_else(|_| "brolly.test".to_string());

    match command {
        "invite" => invite(&pool, &args).await,
        "promote" => set_role(&pool, &args, "admin").await,
        "demote" => set_role(&pool, &args, "member").await,
        "plc-retry" => plc_retry(&pool, &args).await,
        "blob-sweep" => blob_sweep(&pool, &args).await,
        "whoami" => whoami(&pool, &base_domain, &args).await,
        other => {
            eprintln!("unknown command: {other}\n\n{USAGE}");
            ExitCode::FAILURE
        }
    }
}

/// Read `--flag value` out of the argument list.
fn flag(args: &[String], name: &str) -> Option<String> {
    args.iter()
        .position(|a| a == name)
        .and_then(|i| args.get(i + 1))
        .cloned()
}

async fn invite(pool: &sqlx::PgPool, args: &[String]) -> ExitCode {
    let uses: i32 = match flag(args, "--uses").as_deref().map(str::parse) {
        Some(Ok(n)) if n > 0 => n,
        Some(_) => {
            eprintln!("--uses must be a positive integer");
            return ExitCode::FAILURE;
        }
        None => 1,
    };
    let expires = match flag(args, "--expires-days")
        .as_deref()
        .map(str::parse::<i64>)
    {
        Some(Ok(days)) if days > 0 => Some(time::Duration::days(days)),
        Some(_) => {
            eprintln!("--expires-days must be a positive integer");
            return ExitCode::FAILURE;
        }
        None => None,
    };

    let admin = args.iter().any(|a| a == "--admin");
    // An admin invite with several uses is a mistake rather than an intent:
    // the whole point of it is that it is spent. Refusing is cheaper than
    // discovering three admins nobody meant to create.
    if admin && uses != 1 {
        eprintln!("--admin invites are single-use; drop --uses");
        return ExitCode::FAILURE;
    }
    let grants = admin.then_some("admin");

    match brolly_identity::db::create_invite(pool, None, uses, expires, grants).await {
        Ok(code) => {
            // The code itself, alone on stdout, so it can be piped. Everything
            // else goes to stderr — a caller doing `CODE=$(brolly-admin invite)`
            // should get the code and not a paragraph.
            println!("{code}");
            eprintln!(
                "invite created: {uses} use(s){}{}",
                expires
                    .map(|d| format!(", expires in {} days", d.whole_days()))
                    .unwrap_or_default(),
                if admin { ", grants ADMIN" } else { "" }
            );
            eprintln!("this is the only time it is shown; only its hash is stored");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("could not create an invite: {e}");
            ExitCode::FAILURE
        }
    }
}

/// `promote` and `demote` are the same operation with a different target role.
///
/// Demoting the last admin is refused rather than warned about: an instance
/// with no admin cannot be recovered from the web at all, and the operator
/// running this may not be the person who discovers that.
async fn set_role(pool: &sqlx::PgPool, args: &[String], role: &str) -> ExitCode {
    let Some(username) = args.get(1) else {
        eprintln!(
            "usage: brolly-admin {} <username>",
            if role == "admin" { "promote" } else { "demote" }
        );
        return ExitCode::FAILURE;
    };

    let user = match brolly_identity::db::find_by_username(pool, username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            eprintln!("no such member: {username}");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("lookup failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    if user.role == role {
        eprintln!("{username} is already {role}");
        return ExitCode::SUCCESS;
    }

    if role == "member" && user.is_admin() {
        match brolly_identity::db::count_admins(pool).await {
            Ok(1) => {
                eprintln!("{username} is the only active admin; promote someone else first");
                return ExitCode::FAILURE;
            }
            Ok(_) => {}
            Err(e) => {
                eprintln!("could not count admins: {e}");
                return ExitCode::FAILURE;
            }
        }
    }

    match brolly_identity::db::set_role(pool, user.id, role).await {
        Ok(()) => {
            println!("{username}\t{role}");
            // Sessions resolve the user per request, so this is live for
            // anyone already signed in — no re-login, and no stale grant.
            eprintln!("{username} is now {role}; existing sessions see it immediately");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("could not set the role: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn plc_retry(pool: &sqlx::PgPool, args: &[String]) -> ExitCode {
    let dry_run = args.iter().any(|a| a == "--dry-run");

    let pending = match brolly_atproto::identity::unsubmitted(pool).await {
        Ok(pending) => pending,
        Err(e) => {
            eprintln!("could not read the operation log: {e}");
            return ExitCode::FAILURE;
        }
    };

    if pending.is_empty() {
        eprintln!("nothing pending; every operation has been accepted");
        return ExitCode::SUCCESS;
    }
    eprintln!("{} operation(s) awaiting the directory", pending.len());

    if dry_run {
        for entry in &pending {
            println!("{}\t{}", entry.did, entry.cid);
        }
        return ExitCode::SUCCESS;
    }

    // Not `Client::new()`: on a host with no CA bundle, building panics there.
    // Say what's wrong and exit non-zero instead.
    let client = match brolly_server::tls::https_client() {
        Ok(client) => client,
        Err(e) => {
            eprintln!("{e}");
            return ExitCode::FAILURE;
        }
    };
    let mut failed = 0usize;
    for entry in &pending {
        match brolly_atproto::plc::submit(&client, &entry.did, &entry.operation).await {
            Ok(()) => {
                if let Err(e) = brolly_atproto::identity::mark_submitted(pool, &entry.cid).await {
                    eprintln!("{}: submitted but not recorded: {e}", entry.did);
                    failed += 1;
                } else {
                    println!("{}\tsubmitted", entry.did);
                }
            }
            Err(e) => {
                // Retryable and rejected are different problems: one means wait,
                // the other means look. Saying which saves an operator the guess.
                eprintln!(
                    "{}: {e} ({})",
                    entry.did,
                    if e.is_retryable() {
                        "retryable"
                    } else {
                        "will not succeed unchanged"
                    }
                );
                failed += 1;
            }
        }
    }

    if failed > 0 {
        eprintln!("{failed} of {} failed", pending.len());
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

/// ADR 0013's promised orphan sweep, delivered as an operator verb (spec 4,
/// H7): for every member, the pod's `blobs/` directory walked against every
/// digest the metadata graph names. Unreferenced bytes are reported; with
/// `--apply` they are removed.
///
/// Read-only by default, because the diff can be wrong in exactly one way
/// that matters — run against a live server it would report blobs the server
/// is a commit away from referencing — and it cannot even open the stores
/// then: RocksDB lets one process open a directory once, so a running server
/// makes this fail on the instance store before a single pod is reached. Run
/// it with the server stopped.
///
/// `blobs/` only, never the pod directory as a whole: the pod also holds
/// `repo/`, the ATProto repo's CAR blocks, referenced by repo history and not
/// by the resource metadata graph — a whole-pod diff would delete every repo
/// block.
async fn blob_sweep(pool: &sqlx::PgPool, args: &[String]) -> ExitCode {
    let apply = args.iter().any(|a| a == "--apply");
    let data_dir = std::env::var("BROLLY_DATA_DIR").unwrap_or_else(|_| "data".to_string());

    let users = match brolly_identity::db::list_users(pool).await {
        Ok(users) => users,
        Err(e) => {
            eprintln!("could not list members: {e}");
            return ExitCode::FAILURE;
        }
    };

    // The server's own budget numbers: the walk holds one pod at a time, and
    // the LRU keeps a handful open rather than all of them.
    let stores = match brolly_store::StoreManager::open(&data_dir, 4, 60) {
        Ok(stores) => stores,
        Err(e) => {
            eprintln!("could not open the stores under {data_dir}: {e}");
            eprintln!("is the server running? it holds the stores' locks; stop it first");
            return ExitCode::FAILURE;
        }
    };

    let mut failed = 0usize;
    let mut found = 0usize;
    let mut bytes = 0u64;
    for user in users {
        // No pod directory, nothing to sweep — and opening would create one,
        // which a read-only report has no business doing.
        if !stores.pod_exists(user.id) {
            continue;
        }
        // One pod at a time: open it, read the digests its records name, walk
        // `blobs/` against them. A pod that fails to open or read is reported
        // and skipped — the other pods' reports are still worth having.
        let orphans = match (|| {
            let pod = stores.pod(user.id)?;
            let referenced = pod.referenced_blob_digests()?;
            stores.blobs(user.id)?.orphans(&referenced)
        })() {
            Ok(orphans) => orphans,
            Err(e) => {
                eprintln!("{}: could not sweep the pod: {e}", user.username);
                failed += 1;
                continue;
            }
        };
        for orphan in orphans {
            if apply {
                match stores.blobs(user.id).and_then(|b| b.remove(&orphan.digest)) {
                    Ok(()) => println!(
                        "{}\t{}\t{}\tremoved",
                        user.username, orphan.digest, orphan.bytes
                    ),
                    Err(e) => {
                        eprintln!(
                            "{}: {} could not be removed: {e}",
                            user.username, orphan.digest
                        );
                        failed += 1;
                        continue;
                    }
                }
            } else {
                println!("{}\t{}\t{}", user.username, orphan.digest, orphan.bytes);
            }
            found += 1;
            bytes += orphan.bytes;
        }
    }

    eprintln!(
        "{found} orphaned blob(s), {bytes} byte(s){}",
        if apply {
            ", removed"
        } else {
            "; re-run with --apply to remove"
        }
    );
    if failed > 0 {
        eprintln!("{failed} pod(s) could not be swept");
        return ExitCode::FAILURE;
    }
    ExitCode::SUCCESS
}

async fn whoami(pool: &sqlx::PgPool, base_domain: &str, args: &[String]) -> ExitCode {
    let Some(username) = args.get(1) else {
        eprintln!("usage: brolly-admin whoami <username>");
        return ExitCode::FAILURE;
    };

    let user = match brolly_identity::db::find_by_username(pool, username).await {
        Ok(Some(user)) => user,
        Ok(None) => {
            eprintln!("no such member: {username}");
            return ExitCode::FAILURE;
        }
        Err(e) => {
            eprintln!("lookup failed: {e}");
            return ExitCode::FAILURE;
        }
    };

    println!("username   {}", user.username);
    println!("id         {}", user.id);
    println!("status     {}", user.status);
    println!("role       {}", user.role);
    println!(
        "webid      {}",
        brolly_identity::webid::webid(&user.username, base_domain)
    );
    println!(
        "actor      {}",
        brolly_identity::webid::actor(&user.username, base_domain)
    );
    println!(
        "did        {}",
        user.did_plc
            .as_deref()
            .unwrap_or("(none — not provisioned)")
    );

    match brolly_atproto::state::load(pool, user.id).await {
        Ok(Some(state)) => println!("repo       {} (rev {})", state.root_cid, state.rev),
        Ok(None) => println!("repo       (none)"),
        Err(e) => eprintln!("repo       lookup failed: {e}"),
    }

    // Whether the wider network can actually resolve them, which is the
    // question `whoami` is usually being asked to answer.
    match brolly_atproto::identity::head(pool, user.id).await {
        Ok(Some(head)) => println!(
            "plc        {}",
            if head.submitted {
                "registered"
            } else {
                "pending — run `brolly-admin plc-retry`"
            }
        ),
        Ok(None) => println!("plc        (no operations)"),
        Err(e) => eprintln!("plc        lookup failed: {e}"),
    }

    ExitCode::SUCCESS
}
