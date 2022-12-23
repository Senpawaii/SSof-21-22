# Project-Group46

Software Security Course Project for Group 46

## Execution
- For the execution and development of this project we defined new tests that are located in `py_examples` folder.
- The output of this program is placed under the `outputs` directory.
```bash
python3 main.py <input.json> <patterns.json>
```

## AST generation
- If needed, **generate_examples/_generate.py_** takes a source code file (**_.py_** program) and generates the 
corresponding **_.json_** ast, which is stored under **data/** directory
    ### Usage
    ```bash
    python3 generate_examples/generate.py py_examples/<program.py>
    ``` 
  - NOTE: The test program must be located under `py_examples` directory.
  ### Packages required:
    - [ast2json](https://pypi.org/project/ast2json/)