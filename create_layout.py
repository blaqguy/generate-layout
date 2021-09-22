from securesystemslib import interface
from in_toto.models.layout import Layout
from in_toto.models.metadata import Metablock
import yaml
import sys

def main():
  key_owner_path = sys.argv[1]
  key_owner = interface.import_rsa_privatekey_from_file(key_owner_path)

  # key_jenkins_path = sys.argv[2]
  # key_jenkins = interface.import_rsa_privatekey_from_file(key_jenkins_path)

  with open('layout.yml', 'r') as file:
      data = yaml.safe_load(file)
  layout = Layout.read(data)

  key_jenkins_pub = layout.add_functionary_key_from_path('jenkins.pub')
  for step in layout.steps:
      step.pubkeys = [key_jenkins_pub['keyid']]

  metadata = Metablock(signed=layout)

  # Sign and dump layout to "root.layout"
  # Best practice is to sign metadata with more than one owner signature
  # Below is a proof of concept showing how that might be done
  metadata.sign(key_owner)
  # metadata.sign(key_jenkins)
  metadata.dump("root.layout")

if __name__ == '__main__':
  main()
