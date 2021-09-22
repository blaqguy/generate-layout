from securesystemslib.interface import import_rsa_privatekey_from_file
from in_toto.models.layout import Layout, Step, Inspection
from in_toto.models.metadata import Metablock
import sys

#Import and load our layout.yaml file
import yaml
from yaml.loader import  SafeLoader

with open("layout.yaml", "r") as layout_file:
    data = yaml.load(layout_file, Loader=SafeLoader)



# in-toto provides functions to create RSA key pairs if you don't have them yet

"""
Generate owner and jenkins keypair then import owner private key for usage
"""

emeka_key_path = sys.argv[1]
emeka_key = import_rsa_privatekey_from_file(emeka_key_path, password="123")


#Generate Empty layout
layout = Layout()

"""
Add functionary public keys to the layout
Since the functionaries public keys are embedded in the layout, they don't
need to be added separately for final product verification, as a consequence
the layout serves as functionary PKI.
"""

jenkins_pubkey = layout.add_functionary_key_from_path("jenkins.pub")

"""
Set expiration date so that the layout will expire in 30 days from now.
Can also set the expiration to month (months=<number here>)
"""
layout.set_relative_expiration(days=30)

"""
Create layout steps

Each step describes a task that is required to be carried out for a compliant
supply chain.
A step must have a unique name to associate the related link metadata
(i.e. the signed evidence that is created when a step is carried out).

Each step should also list rules about the related files (artifacts) present
before and after the step was carried out. These artifact rules allow to
enforce and authorize which files are used and created by a step, and to link
the steps of the supply chain together, i.e. to guarantee that files are not
tampered with in transit.

A step's pubkeys field lists the keyids of functionaries authorized to
perform the step.

Below step specifies the activity of cloning the source code repo.
Bob is authorized to carry out the step, which must create the product
'demo-project/foo.py'.

When using in-toto tooling (see 'in-toto-run'), Bob will automatically
generate signed link metadata file, which provides the required information
to verify the supply chain of the final product.
The link metadata file must have the name "clone.<bob's keyid prefix>.link"
"""

step_checkout = Step(name=data["checkout"]["step_name"])
step_checkout.pubkeys = [jenkins_pubkey["keyid"]]

# Add expected commands

step_checkout.set_expected_command_from_string(data["checkout"]["command"])

# Check for product/material rules in this step, if exist, add if not, pass.
if data["checkout"].__contains__("material_rules"):
    for material_rule in data["checkout"]["material_rules"]:
        step_checkout.add_product_rule_from_string(material_rule)
elif data["checkout"].__contains__("product_rules"):
    for product_rule in data["checkout"]["product_rules"]:
        step_checkout.add_material_rule_from_string(product_rule)
else:
    pass
    
    
step_lint = Step(name=data["lint"]["step_name"])
step_lint.pubkeys = [jenkins_pubkey["keyid"]]
step_lint.set_expected_command_from_string(data["lint"]["command"])

if data["lint"].__contains__("material_rules"):
    for material_rule in data["lint"]["material_rules"]:
        step_lint.add_product_rule_from_string(material_rule)
elif data["lint"].__contains__("product_rules"):
    for product_rule in data["lint"]["product_rules"]:
        step_lint.add_material_rule_from_string(product_rule)
else:
    pass
    
step_unittest = Step(name=data["unit-test"]["step_name"])
step_unittest.pubkeys = [jenkins_pubkey["keyid"]]
step_unittest.set_expected_command_from_string(data["unit-test"]["command"])

if data["unit-test"].__contains__("material_rules"):
    for material_rule in data["unit-test"]["material_rules"]:
        step_unittest.add_product_rule_from_string(material_rule)
elif data["unit-test"].__contains__("product_rules"):
    for product_rule in data["unit-test"]["product_rules"]:
        step_unittest.add_material_rule_from_string(product_rule)
else:
    pass
    
step_package = Step(name=data["package"]["step_name"])
step_package.pubkeys = [jenkins_pubkey["keyid"]]
step_package.set_expected_command_from_string(data["package"]["command"])

if data["package"].__contains__("material_rules"):
    for material_rule in data["package"]["material_rules"]:
        step_package.add_product_rule_from_string(material_rule)
elif data["package"].__contains__("product_rules"):
    for product_rule in data["package"]["product_rules"]:
        step_package.add_material_rule_from_string(product_rule)
else:
    pass  
        

# Create inspection

inspection = Inspection(name=data["inspect"]["name"])
inspection.set_run_from_string(data["inspect"]["command"])
    
if data["inspect"].__contains__("material_rules"):
    for material_rule in data["inspect"]["material_rules"]:
        inspection.add_material_rule_from_string(material_rule)
elif data["inspect"].__contains__("product_rules"):
    for product_rule in data["inspect"]["product_rules"]:
        inspection.add_product_rule_from_string(product_rule)
else:
    pass    

"""
Inspections are commands that are executed upon in-toto final product
verification. In this case, we define an inspection that untars the final
product, which must match the product of the last step in the supply chain,
('package') and verifies that the contents of the archive match with what was
put into the archive.
"""


# Add steps and inspections to layout
layout.steps = [step_checkout, step_lint, step_unittest, step_package]
layout.inspect = [inspection]

"""
Eventually the layout gets wrapped in a generic in-toto metablock, which
provides functions to sign the metadata contents and write them to a file.
As mentioned above the layout contains the functionaries' public keys and
is signed by the project owner's private key.

In order to reduce the impact of a project owner key compromise, the layout
can and should be be signed by multiple project owners.

Project owner public keys must be provided together with the layout and the
link metadata files for final product verification.
"""


metablock = Metablock(signed=layout)
metablock.sign(emeka_key)
metablock.dump("root.layout")