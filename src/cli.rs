use std::io::Read;

use anyhow::Result;
use clap::{App, AppSettings, Arg, ArgMatches, SubCommand};
use libsshkey::key::{parse_private_pem, EcGroup};
use tracing::{error, info};

use keyd::agent::KeyDAgent;
use keyd::keyd::{GenerateParam, KeyD};
use prettytable::{cell, row, Table};

/// run main cli
pub async fn run(keyd: KeyD) -> Result<()> {
    let args = App::new("keyD")
        .subcommand(SubCommand::with_name("agent").about("run ssh agent"))
        .subcommand(
            SubCommand::with_name("key")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .about("manage key")
                .subcommand(
                    SubCommand::with_name("list").arg(
                        Arg::with_name("group id")
                            .takes_value(true)
                            .help("group id"),
                    ),
                )
                .subcommand(
                    SubCommand::with_name("add")
                        .arg(
                            Arg::with_name("group id")
                                .help("group id, empty for default group")
                                .takes_value(true),
                        )
                        .arg(Arg::with_name("name").help("key name").takes_value(true))
                        .arg(
                            Arg::with_name("path")
                                .help("path to key file, or read from stdin")
                                .takes_value(true),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("remove").arg(
                        Arg::with_name("id")
                            .help("key id to remove")
                            .takes_value(true),
                    ),
                )
                .subcommand(
                    SubCommand::with_name("generate")
                        .arg(
                            Arg::with_name("type")
                                .help("key type")
                                .takes_value(true)
                                .required(true)
                                .possible_values(&["rsa", "ecdsa", "ed25519"]),
                        )
                        .arg(
                            Arg::with_name("bits")
                                .long("bits")
                                .short("b")
                                .help("bits")
                                .takes_value(true),
                        )
                        .arg(
                            Arg::with_name("tpm")
                                .long("tpm")
                                .conflicts_with("pkcs11")
                                .help("generate using tpm"),
                        )
                        .arg(
                            Arg::with_name("pkcs11")
                                .long("pkcs11")
                                .conflicts_with("tpm")
                                .help("generate using pkcs11"),
                        )
                        .arg(
                            Arg::with_name("save")
                                .long("save")
                                .short("s")
                                .help("save into keyd after generated")
                                .requires("private out"),
                        )
                        .arg(
                            Arg::with_name("name")
                                .long("name")
                                .short("n")
                                .help("name saved into key store")
                                .requires("save")
                                .takes_value(true)
                        )
                        .arg(
                            Arg::with_name("group id")
                                .long("group")
                                .short("g")
                                .help("group id, empty for default group")
                                .requires("save")
                                .takes_value(true)
                        )
                        .arg(Arg::with_name("private out"))
                        .arg(
                            Arg::with_name("comment")
                                .long("comment")
                                .short("c")
                                .help("comment")
                                .takes_value(true),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("get")
                        .about("get key")
                        .help("get key")
                        .arg(
                            Arg::with_name("id | name")
                                .takes_value(true)
                                .required(true)
                        )
                        .arg(
                            Arg::with_name("private")
                                .long("private")
                                .short("p")
                                .help("show private key")
                        )
                ),
        )
        .subcommand(
            SubCommand::with_name("group")
                .setting(AppSettings::SubcommandRequiredElseHelp)
                .about("manage group")
                .subcommand(
                    SubCommand::with_name("add").about("add key group").arg(
                        Arg::with_name("name")
                            .help("group name")
                            .takes_value(true)
                            .required(true),
                    ),
                )
                .subcommand(SubCommand::with_name("list").about("list key groups"))
                .subcommand(
                    SubCommand::with_name("rename")
                        .about("rename group")
                        .arg(
                            Arg::with_name("id")
                                .value_name("id|name")
                                .help("group id or name")
                                .takes_value(true)
                                .required(true),
                        )
                        .arg(
                            Arg::with_name("new name")
                                .help("new name")
                                .takes_value(true)
                                .required(true),
                        ),
                )
                .subcommand(
                    SubCommand::with_name("remove")
                        .about("remove group, only empty group")
                        .arg(
                            Arg::with_name("id")
                                .visible_alias("name")
                                .takes_value(true)
                                .required(true),
                        ),
                ),
        )
        .get_matches();

    if let Some(args) = args.subcommand_matches("group") {
        run_group(args, keyd).await?;
        return Ok(());
    }

    if let Some(args) = args.subcommand_matches("agent") {
        run_agent(args, keyd).await?;
        return Ok(());
    }

    if let Some(args) = args.subcommand_matches("key") {
        run_key(args, keyd).await?;
        return Ok(());
    }

    Ok(())
}

/// handle agent command
/// run agent
async fn run_agent(_args: &ArgMatches<'_>, keyd: KeyD) -> Result<()> {
    let path = {
        match std::env::var("AGENT_SOCK") {
            Ok(path) => std::path::PathBuf::from(path),
            Err(_) => std::env::temp_dir().join(format!("keyd-agent.{}", std::process::id())),
        }
    };

    let agent = KeyDAgent::new(keyd).unwrap();
    {
        let path = path.clone();
        tokio::spawn(async move {
            agent.run(path).await.ok();
        });
    }

    tokio::signal::ctrl_c().await?;

    std::fs::remove_file(path).ok();

    Ok(())
}

/// handle group subcommand
async fn run_group(args: &ArgMatches<'_>, keyd: KeyD) -> Result<()> {
    match args.subcommand() {
        ("add", Some(args)) => {
            let name = args.value_of("name").unwrap();
            let id = keyd.create_group(name).await?;

            info!("group added, id: {}", id);
        }
        ("list", _) => {
            let groups = keyd.list_groups().await?;
            dbg!(groups);
        }
        ("rename", Some(args)) => {
            let id = args.value_of("id").unwrap();
            let new_name = args.value_of("new name").unwrap();

            let id = id.parse::<i64>()?;
            keyd.rename_group(id, new_name).await?;

            info!("group {} rename to {}", id, new_name);
        }
        ("remove", Some(args)) => {
            let id = args
                .value_of("id")
                .and_then(|it| it.parse::<i64>().ok())
                .unwrap();

            if id == 1 {
                error!("can't remove default group");
                return Ok(());
            }

            keyd.delete_group(id).await?;

            info!("remove group {}", id);
        }
        _ => unreachable!(),
    }

    Ok(())
}

/// handle keys subcommand
async fn run_key(args: &ArgMatches<'_>, mut keyd: KeyD) -> Result<()> {
    match args.subcommand() {
        ("add", Some(args)) => {
            let group_id = args
                .value_of("group id")
                .and_then(|it| it.parse::<i64>().ok());
            let name = args.value_of("name");
            let path = args.value_of("path");

            // read content from path or stdin
            let content = match path {
                Some(path) => std::fs::read_to_string(path)?,
                None => {
                    let stdin = std::io::stdin();
                    let mut stdin = stdin.lock();
                    let mut key = String::new();

                    let _r = stdin.read_to_string(&mut key)?;

                    key
                }
            };

            // convert pem to raw ssh key in `libsshkey`
            let key = parse_private_pem(content.as_bytes(), None::<&str>)?;

            // add to KeyStore
            let item = keyd.add(group_id, name, key).await?;
            info!("key {} added", item.public());
        }
        ("list", Some(args)) => {
            let group_id = args
                .value_of("group id")
                .and_then(|it| it.parse::<i64>().ok());
            match group_id {
                Some(group_id) => {
                    let keys = keyd.list_group_keys(group_id).await?;
                    let mut table = Table::new();
                    table.set_titles(row!["ID", "Name", "KeyType", "Fingerprint", "PublicKey",]);

                    for k in keys {
                        table.add_row(row![
                            k.item.id,
                            k.item.name,
                            k.item.key_type,
                            k.item.meta.fingerprint,
                            k.public()[0..32],
                        ]);
                    }

                    table.printstd();
                }
                None => {
                    let keys = keyd.get_all().await?;
                    let mut table = Table::new();
                    table.set_titles(row![
                        "ID",
                        "Name",
                        "KeyType",
                        "Fingerprint",
                        "PublicKey",
                        "GroupId"
                    ]);

                    for k in keys {
                        table.add_row(row![
                            k.item.id,
                            k.item.name,
                            k.item.key_type,
                            k.item.meta.fingerprint,
                            k.public()[0..32],
                            k.item.group_id.unwrap(),
                        ]);
                    }

                    table.printstd();
                }
            }
        }
        ("remove", Some(args)) => {
            let id = args
                .value_of("id")
                .and_then(|it| it.parse::<i64>().ok())
                .unwrap();
            let _ = keyd.remove(id).await?;

            info!("key {} removed", id);
        }
        ("generate", Some(args)) => {
            let key_type = args.value_of("type").unwrap();
            let bits = args
                .value_of("bits")
                .and_then(|it| it.parse::<u32>().ok())
                .unwrap();
            let comment = args.value_of("comment").map(|it| it.to_owned());
            let save = args.is_present("save");

            let param = match key_type {
                "rsa" => GenerateParam::Rsa(bits),
                "ecdsa" => match bits {
                    256 => GenerateParam::Ecdsa(EcGroup::P256),
                    384 => GenerateParam::Ecdsa(EcGroup::P384),
                    521 => GenerateParam::Ecdsa(EcGroup::P521),
                    _ => anyhow::bail!("unsupported bits in ecdsa"),
                },
                "ed25519" => todo!(),
                _ => unreachable!(),
            };

            if args.is_present("tpm") {
                todo!("generate tpm");
            } else if args.is_present("pkcs11") {
                todo!("generate pkcs11");
            } else {
                let key = keyd.generate_managed(param, comment).await?;

                if save {
                    let group_id = args
                        .value_of("group id")
                        .and_then(|it| it.parse::<i64>().ok());
                    let name = args.value_of("name");

                    let item = keyd.add(group_id, name, key.clone()).await?;

                    if name.is_none() {
                        info!("key {} added", item.item.name);
                    }
                }

                println!("{}", key.export_private_pem()?);
            }
        }
        ("get", Some(args)) => {
            let arg = args.value_of("id | name").unwrap();
            let show_private = args.is_present("private");

            let key = match arg.parse::<i64>() {
                Ok(id) => {
                    keyd.get_by_id(id).await?
                },
                Err(_) => {
                    keyd.get_by_name(arg).await?
                }
            };

            println!("{}", key.public());

            if show_private {
                println!("{}", key.private()?);
            }
        }
        _ => unreachable!(),
    }
    Ok(())
}
