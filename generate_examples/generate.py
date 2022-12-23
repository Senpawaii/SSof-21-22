import json
import sys
from ast import parse
from ast2json import ast2json

file_name = sys.argv[1]
file_name = file_name.replace(".py", "")
source_py = f"py_examples/{file_name}.py"
source_json = f"py_examples/{file_name}.json"
output_json = f"data/{file_name}.json"
ast = ast2json(parse(open(source_py).read()))

ast = json.dumps(ast, indent=4)

remove = "_type"

# Replace the target string
ast = ast.replace(remove, "ast_type")

# Write the file out again
with open(output_json, "w") as file:
    file.write(ast)