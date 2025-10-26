# Our server seems to be leaking pieces of a secret flag in its logs. The parts are scattered and sometimes repeated. Can you reconstruct the original flag? Download the logs and figure out the full flag from the fragments.
# I have not included the logs here, download them from the picoCTF challenge page.

# Read from server.log and extract lines containing "INFO FLAGPART:"
input_file = "server.log"

with open("server.log", "r") as f:
    for line in f:
        if "INFO FLAGPART:" in line:
            print(line.strip())
