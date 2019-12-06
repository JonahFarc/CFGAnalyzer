import cfg

def check(attack, path):
  attack_length = len(attack)
  path_length = len(path)
  
  if path_length < attack_length
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
  
attack_list = []

# For each attack vector to detect, include its sequence of function calls here & append to attack_list
attack1 = ['socket', 'bind', 'listen', 'accept', 'decode', 'Popen']
attack_list.append(attack1)

# get list of each path of function calls for the file
function_calls_list = cfg.get_call_paths()

# Check if attack vector exists in code
for attack in range(len(attack_list)):
  attack_found = False
  for path in range(len(function_calls_list)):
    attack_found = check(attack_list[attack], function_calls_list[path])
    if attack_found:
      print("-------------------------------------------------------------------------------------------")
      print("Possible attack found: ")
      print(attack_list[attack])
      print("Found at path: ")
      print(function_calls_list[path])
      print("-------------------------------------------------------------------------------------------")
      attack_found = False
