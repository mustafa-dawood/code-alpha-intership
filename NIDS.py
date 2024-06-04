import os

snort_config_file = "/etc/snort/snort.conf"
snort_rules_dir = "/etc/snort/rules/"
snort_interface = "eth0"


def configure_snort():

    if not os.path.exists(snort_config_file):
        with open(snort_config_file, "w") as file:
            file.write("""
            # تكوين Snort
            var HOME_NET any
            var EXTERNAL_NET any
            """)


    if not os.path.exists(snort_rules_dir):
        os.makedirs(snort_rules_dir)

    with open(snort_rules_dir + "local.rules", "w") as file:
        file.write("""
        alert tcp any any -> $HOME_NET any (msg:"Port Scan Detected"; flags:S; threshold: type limit, count 5, seconds 60; sid:1000001; rev:1;)
        """)


def run_snort():

    os.system(f"snort -c {snort_config_file} -i {snort_interface} -D")


if __name__ == "__main__":
    configure_snort()
    run_snort()