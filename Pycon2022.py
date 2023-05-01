###
# From the talk "Aaron Stephens: Python for Threat Intelligence" at PyCon US 2022
# https://www.youtube.com/watch?v=Zf38qncahiU
###

### Argument parsing
from argparse import ArgumentParser

parser = ArgumentParser(description="Threat Intel utility")
parser.add_argument("md5", help="MD5 Hash")

args = parser.parse_args()

LOG_ARG = ArgumentParser(add_help=False)
LOG_ARG.add_argument("-l", "--log", help="logging output level", metavar="level")

### Use arguments across files
# base of arguments used across projects
from .core.args import LOG_ARG

parser = ArgumentParser(description="More Threat Intelligence", parents=[LOG_ARG])

### Logging
from logging import getLogger, Streamhandler

LOG = getLogger("logger.name") # or __name__

def testing(one: int, two:int) -> None:
  LOG.debug("Calculating the maths of %s + %s", one, two)
  print(one + two)
  
# After arguments have been parsed
LOG.setLevel(args.log)
LOG.addHandler(StreamHandler())

testing(args.one, args.two)

### File I/O, HTTP Requests, and Error Handling
from json import dump

data = {"key": "value"}
path = "example.json"

# Dumping json data into a specified file
with open(path, "w") as json_file:
  LOG.info("Writing JSON to %s.", path)
  dump(data, json_file)
  
from httpx import get, Response

def request(url: str) -> Response:
  LOG.debug("Making GET request for %s.", url)
  response = get(url)
  status = response.status_code
  # Log if we got a 200, 301, 404, etc. 
  LOG.debug("Got a %d response.", status) 
  # We are expecting a Response to be returned from this request
  return response

def parsing_data(data):
  for i, item in enumerate(data):
    try:
      parse(item)
    except:
      msg = "Failed to parse item %d: %s."
      # Logging the message AND the traceback
      LOG.exception(msg, i, item)

### RICH syntax for console utilities
# Provides tables, syntax, markdown, tracebacks, progress bars, and more features for the UI/UX of CLI
# Read more at https://rich.readthedocs.io/en/stable/
from rich import print

# Highlight file paths
print("Loading DNS data from /dnslogs/marchlog")

# Add colors to output, IP addresses automatically colored
print("[red]badbadbadbadbadguy.com[/] resolved to 127.0.0.1")

# Emojis work too along with simple styling
print(":police_car_light: This is [bold]SERIOUS[/]!")

### More RICH
from rich.console import Console
from rich.highlighter import RegexHighlighter
from rich.theme import Theme

class MD5Highlighter(RegexHighlighter):
  """Highlight MD5 hashes."""
  
  base_style = "hash."
  # How would you change this to SHA256? ;)
  highlights = [r"(?P<md5>[a-fA-F\d]{32})"]

theme = Theme({"hash.md5": "bold underline red"})
console = Console(highlighter=MD5Highlighter(), theme=theme)

console.print("Evil malware detected: bbfd5719bda53fd4c86c400643d123e5")

### RICH Logging
# That is right, RICH even has its own logger.
from logging import getLogger
from rich.logging import RichHandler

LOG = getLogger("rich.logging")
LOG.addHandler("RichHandler()")
LOG.setLevel("DEBUG")

LOG.info("Testing logging out... 1, 2, 3")
LOG.debug("Analyzing IP at 127.0.0.1")

### HTTPX continued 
# Handles async and sync depending on use case
# The next-gen HTTP client for python utilities
# Encode also provides starlette and uvicorn libs
from asyncio import run
from httpx import get, AsyncClient, Response

async def async_get(url: str) -> Response:
  async with AsyncClient() as client:
    response = await client.get(url)
  return response

url = "https://github.com/"

# Synchronous
response = get(url)

# asynchronous
response = run(async_get(url))

### HTTPX Event Hooks
from httpx import Client, Request
from .core.auth import get_token

def add_auth(request: Request) -> None:
  # Header is added only for a specific host
  if request.url.host == "api.service.com":
    request.headers["Authorization"] = get_token()
    
client = Client(event_hooks ={"request": [add_auth]})
url = "https://api.service.com/endpoint"
params = {"fqdn": "badguy.net"}

# Auth header is added automatically thanks to add_auth
response = client.get(url, params=params)

### MODELING
# A simple class for Nodes and Edges
class Node:
  """ A data model node. """
  def __init__(self, _type: str, **properties):
    self.type = _type
    self.properties = properties
    self.tags = []
  
  def tag(self, label:str) -> None:
    self.tags.append(label)
  
class Edge:
  """ A data model edge. """
  def __init__(self, _type:str, n1: Node, n2: Node, **properties):
    self.type = _type
    self.properties = properties
    self.n1 = n1
    self.n2 = n2
    
# Can use these to build a data model that also validates what is passed in
class DataModel:
  def __init__(self):
    self.nodes = []
    self.edges = []
  
  def file(self, md5: str, name: str | None = None) -> Node:
    """ A node representing a file or sequence of bytes. """
    node = Node("file", md5=md5, name=name)
    self.nodes.append(node)
    return node
  
  def contains(self, n1: Node, n2: Node) -> Edge:
    """ An edge representing one file containing another. """
    if n1.type != "file" or n2.type != "file":
      raise ValueError("Both nodes must be files!")
      
    edge = Edge("contains", n1=n1, n2=n2)
    self.edges.append(edge)
    return edge

# Transform Nodes and Edges into a payload that can be submitted to our API
# while also using the same networking stack we built up previously
from .core.network import AuthClient 
  # ...further down in the DataModel
  def create_payload(self) -> list:
    """ Create payload from data model."""
    payload = []
    # TODO: Parse nodes and edges.
    return payload
  
  def submit(self) -> None:
    """ Submit data model to graph."""
    url = "https://api.internal.com/graph"
    payload = self.create_payload()
    
    with AuthClient() as client:
      response = client.post(url, json=payload)
      
    # TODO: Handle response.
    # After all, you want to make sure the API successful adds your models.

# Modeling network scan data
    
from .core.model import DataModel
def model_scans(dm: DataModel, scans: list) -> None:
  """ Model network scan data for IP."""
  
  for scan in scans:
    ip = scan["ip"]
    port = scan["port"]
    ipport = dm.ipport(f"{ip}:{port}")
    
    if tls := scan.get("tls"):
        cert = parse_certificate(tls)
        node = dm.file(cert.md5)
        
        if cert.selfissued:
          node.tag("x509.selfissued")
          
        dm.serves(ipport, node)
dm = DataModel()
# Get data from source
scans = ip_scans("123.45.67.89")

# Model data
model_scans(dm, scans)

# Show user and submit to graph
dm.display()
dm.submit(prompt=True)

### INSPECTING FILES
from datetime import datetime
from hashlib import md5

from pefile import PE

with open("explorer.exe", "rb") as pe_file:
  pe_bytes = pe_file.read()
  pe = PE(data=pe_bytes)
  
timestamp = pe.FILE_HEADER.TimeDateStamp
compiled = datetime.utcfromtimestamp(timestamp)

print(f"MD5 {md5(pe_bytes).hexdigest()}")
print(f"Compiled on {compiled} UTC")
#Undocumented header in PE files that contains build environment
#https://github.com/RichHeaderResearch/RichPE
print(f"Rich Hash {pe.get_rich_header_hash()}")
#Gets the import table hashes
#https://forensicitguy.github.io/rich-header-hashes-with-pefile/
print(f"Import Hash {pe.get_imphash()}") 

### INSPECTING FILES
# What is async1crypto?
# It is a lib for parsing and serializing ASN.1 structs
# https://github.com/wbond/asn1crypto
from asyn1crypto.cms import ContentInfo

# The PE is loaded in already
offset = 0
length = 0
name = "IMAGE_DIRECTORY_ENTRY_SECURITY"

for struct in pe.__structures__:
  if struct.name == name:
    offset = struct.VirtualAddress
    length = struct.Size
    break
  
data = pe_bytes[offset + 8 : offset + length]
content = ContentInfo.load(data)["content"]

# x.509 certificate chain
certificates = content["certificates"]

# Now we can pull out data points from those files that interest us
# Such as in the x.509 certificates
from asn1crypto.x509 import Certificate, Name

def print_cert(cert: Certificate) -> None:
  serial = cert.serial_number
  print(f"Serial: {serial}")
  
  def name_string(name: Name) -> str:
    items = [i.hashable for i in name.chosen]
    string = "\n  ".join(items)
    return f"  {string}"

  print(f"Subject\n{name_string(cert.subject)}")
  print(f"Issuer\n{name_string(cert.issuer)}\n")
  
# After loading certificates
for certificate in certificates:
  print_cert(certificate.chosen)
  
### YARA
# https://virustotal.github.io/yara/
# Industry standard for pattern matching rules

# After we parse the PE and certificate
# We would also want to check if the rule name does not already exist
# and log an error there 
def cert_yara_rule(serial_number: int, common_name: str) -> str:
  # Returns a generated YARA rule that checks for a PE header, cert serial number in hex,
  # and the common name encoded as hex.
  # Another benefit is that the rule name is generated using the cert serial number
  return f"""
  rule certificate_{serial_number} {{
    strings:
      $sn = {{ {hex(serial_number)} }}
      $cn = {{ {common_name.encode().hex()} }}
    condition:
      (uint16(0) == 0x5A4D) and $sn and $cn
  }}
  """

def rich_hash_yara_rule(pe: PE) -> str:
  rich_hash = pe.get_rich_header_hash()
  return f"""
  rule rich_hash_{rich_hash} {{
    condition:
      hash.md5(pe.rich_signature.clear_data) == "{rich_hash}"
  }}
  """

### GENERAL ADVICE
# Start small and go through Automate The Boring Stuff
# https://automatetheboringstuff.com/#toc

# Use VSCode as your IDE, Formatting in black and Linting in pylint
# https://code.visualstudio.com/
# https://github.com/psf/black
# https://pypi.org/project/pylint/
