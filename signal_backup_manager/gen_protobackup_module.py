import requests
import subprocess

BACKUPS_PROTO_URI = ("https://raw.githubusercontent.com/"
                     "signalapp/Signal-Android/master/protobuf/Backups.proto")


def generate_protobackup_module():

    r = requests.get(BACKUPS_PROTO_URI)

    with open('Backups.proto', 'w') as bkp_proto_file:
        bkp_proto_file.write(r.text)

    subprocess.run([
        'protoc', '--proto_path=.', '--python_out=.', 'Backups.proto'
    ])


if __name__ == "__main__":
    generate_protobackup_module()
