set -l subcommands (certigo --completion-bash)
complete -c certigo -f -n "not __fish_seen_subcommand_from $subcommands" -a "$subcommands"
complete -c certigo -n "not __fish_seen_subcommand_from $subcommands" -a "(certigo --completion-bash --)"

complete -c certigo -f -n "__fish_seen_subcommand_from help" -a "(certigo --completion-bash help --)"

complete -c certigo -F -n "__fish_seen_subcommand_from dump" -a "(certigo --completion-bash dump --)"
complete -c certigo -n "__fish_seen_subcommand_from dump" -a "-f -p"
complete -c certigo -n "__fish_seen_subcommand_from dump" -s f -l format -x
complete -c certigo -n "__fish_seen_subcommand_from dump" -s p -l password -x

complete -c certigo -f -n "__fish_seen_subcommand_from connect" -a "(certigo --completion-bash connect --)"
complete -c certigo -n "__fish_seen_subcommand_from connect" -a "-n -t"
complete -c certigo -n "__fish_seen_subcommand_from connect" -s n -l name -x
complete -c certigo -n "__fish_seen_subcommand_from connect" -l ca -r -a "(__fish_complete_path)"
complete -c certigo -n "__fish_seen_subcommand_from connect" -l cert -r -a "(__fish_complete_path)"
complete -c certigo -n "__fish_seen_subcommand_from connect" -l key -r -a "(__fish_complete_path)"
complete -c certigo -n "__fish_seen_subcommand_from connect" -s t -l start-tls -x -a "(certigo --completion-bash connect --start-tls)"
complete -c certigo -n "__fish_seen_subcommand_from connect" -l identity -x
complete -c certigo -n "__fish_seen_subcommand_from connect" -l proxy -x
complete -c certigo -n "__fish_seen_subcommand_from connect" -l timeout -x
complete -c certigo -n "__fish_seen_subcommand_from connect" -l expected-name -x

complete -c certigo -F -n "__fish_seen_subcommand_from verify" -a "(certigo --completion-bash verify --)"
complete -c certigo -n "__fish_seen_subcommand_from verify" -a "-f -p -n"
complete -c certigo -n "__fish_seen_subcommand_from verify" -s f -l format -x
complete -c certigo -n "__fish_seen_subcommand_from verify" -s p -l password -x
complete -c certigo -n "__fish_seen_subcommand_from verify" -s n -l name -x
complete -c certigo -n "__fish_seen_subcommand_from verify" -l ca -r -a "(__fish_complete_path)"
