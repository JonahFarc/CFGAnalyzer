import cfg
import argparse

def check(attack, path):
  attack_length = len(attack)
  path_length = len(path)
  
  if path_length < attack_length:
    return False
    
  start = 0
  function_found = False
  for i in range(attack_length):
    for j in range(start, path_length):
      if attack[i] == path[j]:
        start = j + 1
        function_found = True
        break
    if not function_found:
      return False
    else:
      function_found = False
  return True
  
parser = argparse.ArgumentParser()
parser.add_argument('-s','--source', action='store_true', help='print source code')
args = parser.parse_args()

attack_list = []

# For each attack vector to detect, include its sequence of function calls here & append to attack_list
attack1 = ['socket', 'bind', 'listen', 'accept', 'decode', 'Popen']
attack_list.append(attack1)

# get list of each path of function calls for the file
function_calls_list, node_calls_list = cfg.get_call_paths()

# Check if attack vector exists in code
for attack in attack_list:
  for call_path, node_call_path in zip(function_calls_list, node_calls_list):
    if check(attack, call_path):
      print("-------------------------------------------------------------------------------------------")
      print("Possible attack found: ")
      print(attack)
      print("Found at path: ")
      print(call_path)
      print("Line numbers: ")
      print([x.rid for x in node_call_path])
      if args.source:
        print("Source: ")
        for x in node_call_path:
          print(x.source())

      print("-------------------------------------------------------------------------------------------")
