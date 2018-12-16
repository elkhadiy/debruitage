import argparse

from signal_backup_manager.signal_backup import SignalBackup


def run():
    parser = argparse.ArgumentParser(
        prog='Signal Backup Decryptor',
        description="Decrypts a Signal backup."
    )

    parser.add_argument(
        '-b', '--backup-file',
        help='Path to signal backup file'
        )
    parser.add_argument(
        '-p', '--passphrase',
        help='Backup file passphrase'
    )

    args = parser.parse_args()

    bkp = SignalBackup(args.backup_file, args.passphrase)


if __name__ == "__main__":
    run()
