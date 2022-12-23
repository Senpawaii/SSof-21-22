import json
import sys
from dataclasses import dataclass


class Parser:
    def check_type(self, d):
        if d['ast_type'] == "Expr":
            return Expr(d)
        elif d['ast_type'] == "Call":
            return Call(d)
        elif d['ast_type'] == "Constant":
            return Constant(d)
        elif d['ast_type'] == "Name":
            return Name(d)
        elif d['ast_type'] == "BinOp":
            return BinOp(d)
        elif d['ast_type'] == "Assign":
            return Assign(d)
        elif d['ast_type'] == "Attribute":
            return Attribute(d)
        elif d['ast_type'] == "Compare":
            return Compare(d)
        elif d['ast_type'] == "If":
            return If(d)
        elif d['ast_type'] == "While":
            return While(d)
        elif d['ast_type'] == "Break":
            return Break(d)
        elif d['ast_type'] == "Continue":
            return Continue(d)
        elif d['ast_type'] == "Pass":
            return Pass(d)
        else:
            print(f"Node type {d['ast_type']} not recognized. Too bad...")
            exit(1)


class Pass(Parser):
    def __init__(self, line):
        pass

    def eval(self):
        return {"Pass": "empty"}


class Continue(Parser):
    def __init__(self, line):
        pass

    def eval(self):
        return {"Continue" : "empty"}


class Break(Parser):
    def __init__(self, line):
        pass

    def eval(self):
        return {"Break": "empty"}


class While(Parser):
    def __init__(self, line):
        self.body = line['body']
        self.test = line['test']

    def eval(self):
        body_list = list()
        test_parser = self.check_type(self.test)

        for line in self.body:
            body_parser = self.check_type(line)
            body_list.append(body_parser.eval())

        key_val = {"test": test_parser.eval(), "body": body_list}
        return {"While": key_val}


class If(Parser):
    def __init__(self, line):
        self.body = line['body']
        self.orelse = line['orelse']
        self.test = line['test']

    def eval(self):
        test_parser = self.check_type(self.test)
        body_list = list()
        orelse_list = list()

        for bline in self.body:
            bline_parser = self.check_type(bline)
            body_list.append(bline_parser.eval())

        for oritem in self.orelse:
            oritem_parser = self.check_type(oritem)
            orelse_list.append(oritem_parser.eval())

        key_val = {"test": test_parser.eval(), "body": body_list, "orelse": orelse_list}
        return {"If": key_val}


class Compare(Parser):
    def __init__(self, line):
        self.left = line['left']
        self.comparators = line['comparators']
        self.ops = line['ops']

    def eval(self):
        left_parser = self.check_type(self.left)
        comparators_list = list()
        for idx, op in enumerate(self.ops):
            comparator_parser = self.check_type(self.comparators[idx])
            comparators_list.append({"op": op, "comparator": comparator_parser.eval()})
        key_val = {"left": left_parser.eval(), "comparators": comparators_list}
        return {"Compare": key_val}


class Attribute(Parser):
    def __init__(self, line):
        self.attr = line['attr']
        self.ctx = line['ctx']['ast_type']
        self.value = line['value']

    def eval(self):
        val_parser = self.check_type(self.value)
        key_val = {"attr": self.attr, "ctx": self.ctx, "value": val_parser.eval()}
        return {"Attribute": key_val}


class Assign(Parser):
    def __init__(self, line):
        self.targets = line['targets']
        self.value = line['value']

    def eval(self):
        targs_results = list()
        for targ in self.targets:
            targ_parser = self.check_type(targ)
            targs_results.append(targ_parser.eval())
        val_parser = self.check_type(self.value)
        key_val = {"targets": targs_results, "value": val_parser.eval()}
        return {"Assign": key_val}


class BinOp(Parser):
    def __init__(self, line):
        self.right = line['right']
        self.left = line['left']
        self.op = line['op']['ast_type']

    def eval(self):
        right_parser = self.check_type(self.right)
        left_parser = self.check_type(self.left)
        key_val = {"op": self.op, "left": left_parser.eval(), "right": right_parser.eval()}
        return {"BinOp": key_val}


class Name(Parser):
    def __init__(self, line):
        self.id = line['id']
        self.ctx = line['ctx']['ast_type']

    def eval(self):
        key_val = {"id": self.id, "ctx": self.ctx}
        return {"Name": key_val}


class Constant(Parser):
    def __init__(self, line):
        self.value = line['value']

    def eval(self):
        return {"Constant": self.value}


class Call(Parser):
    def __init__(self, line):
        self.args = line['args']
        self.func = line['func']
        self.keywords = line['keywords']

    def eval(self):
        args_results = list()

        for arg in self.args:
            arg_parser = self.check_type(arg)
            args_results.append(arg_parser.eval())

        func_parser = self.check_type(self.func)

        for karg in self.keywords:
            k_parser = self.check_type(karg['value'])
            args_results.append(k_parser.eval())

        key_val = {"args": args_results, "func": func_parser.eval()}
        return {"Call": key_val}


class Expr(Parser):
    def __init__(self, line):
        self.value = line['value']

    def eval(self):
        # type_as = self.value['ast_type']
        parser = self.check_type(self.value)
        return parser.eval()


def is_source(v, sources):
    if "Call" in v.keys():
        func_name = v["Call"]["func"]["Name"]["id"]
        return func_name in sources, func_name
    return False, ""


def is_sanitizer(v, sanitizers):
    func_name = v["Call"]['func']['Name']['id']
    if func_name in sanitizers:
        return True, func_name
    return False, ""


def analyze_type(line, vuln, implicit, implicit_flows, pending, initialized, level=0):
    """ The assign key is present in source and sanitizing cases """
    if "Assign" in line.keys():
        new_flows = analyze_assign(line['Assign'], vuln, implicit, implicit_flows, pending, initialized, level).copy()
    elif "Call" in line.keys():
        new_flows = analyze_call(line['Call'], vuln, implicit, implicit_flows, pending, initialized, level).copy()
    elif "Constant" in line.keys():
        new_flows = []
    elif "Name" in line.keys():
        new_flows = []
        analyze_name(line['Name'], new_flows, vuln, implicit, implicit_flows, pending, initialized, level)
    elif "BinOp" in line.keys():
        new_flows = analyze_binop(line['BinOp'], vuln, implicit, implicit_flows, pending, initialized, level).copy()
    elif "Compare" in line.keys():
        new_flows = analyze_compare(line['Compare'], vuln, implicit, implicit_flows, pending, initialized, level).copy()
    elif "If" in line.keys():
        new_flows = analyze_if(line['If'], vuln, implicit, implicit_flows, pending, initialized, level).copy()
    elif "While" in line.keys():
        new_flows = analyze_while(line['While'], vuln, implicit, implicit_flows, pending, initialized, level).copy()
    elif "Break" in line.keys():
        new_flows = []
    elif "Continue" in line.keys():
        new_flows = []
    elif "Pass" in line.keys():
        new_flows = []
    elif "Attribute" in line.keys():
        new_flows = analyze_attribute(line['Attribute'], vuln, implicit, implicit_flows, pending, initialized, level).copy()
    else:
        print(f"Ast type not recognized. Too bad...")
        exit(1)
    return new_flows


def getID(target):
    if "Name" in target.keys():
        return target['Name']['id']
    else:
        return getID(target['value']) + "." + target['attr']


def analyze_attribute(att_dict, vuln, implicit, implicit_flows, pending, initialized, level):
    ctx = att_dict['ctx']
    parents_str = getID(att_dict)
    names_list = parents_str.split(".")
    names_dict = dict()
    new_flows = list()

    for name in names_list:
        if initialized:
            name_entries = list(filter(lambda entry: name in entry.keys(), initialized))
            name_values = [d[name] for d in name_entries if d[name] <= level]
        else:
            name_values = list()
        names_dict[name] = name_values.copy()

        if name in vuln['sources'] or (ctx == "Load" and not names_dict[name]):
            imp_str = "yes" if implicit else "no"
            new_flow = Flow(source=name, sink="", var="", sanitizer=[], implicit=imp_str, tainted=True)
            new_flows.append(new_flow)

    for pending_flow in pending:
        if pending_flow.var in names_list:
            dup_flow = Flow(source=pending_flow.source,
                            sink=pending_flow.sink,
                            var=pending_flow.var,
                            sanitizer=pending_flow.sanitizer.copy(),
                            implicit=pending_flow.implicit,
                            tainted=pending_flow.tainted)
            new_flows.append(dup_flow)
    return new_flows


def analyze_while(while_dict, vuln, implicit, implicit_flows, pending, initialized, level):
    final_flows = list()
    body = while_dict['body']
    test = while_dict['test']
    new_level = level + 1
    equal = False
    while(not equal):
        test_flows = analyze_type(test, vuln, implicit, implicit_flows, pending, initialized, level)

        if implicit:
            for flow in test_flows:
                if not flow.sink and flow.source not in implicit_flows:
                    implicit_flows.append(flow)

        initialized_dup = initialized.copy()
        pending_dup = pending.copy()
        body_flows = list()

        for node in body:
            body_flows += analyze_type(node, vuln, implicit, implicit_flows, pending_dup, initialized_dup, new_level)

        initialized_dups = initialized_dup + initialized
        unique_initialized = []

        for d in initialized_dups:
            if d not in unique_initialized:
                unique_initialized.append(d)

        lst_dups = list(set(pending_dup))
        new_pending = list(set(pending + lst_dups))

        initialized.clear()
        initialized += unique_initialized

        pending.clear()
        pending += new_pending

        unique_flows = list(set(body_flows + test_flows))
        compare_final = list(set(final_flows + unique_flows))
        if set(compare_final) == set(final_flows):
            equal = True
        else:
            final_flows = compare_final.copy()

    return final_flows


def analyze_if(if_dict, vuln, implicit, implicit_flows, pending, initialized, level):
    body = if_dict['body']
    orelse = if_dict['orelse']
    test = if_dict['test']
    new_level = level + 1
    test_flows = analyze_type(test, vuln, implicit, implicit_flows, pending, initialized, level)

    if implicit:
        for flow in test_flows:
            if not flow.sink and flow.source not in implicit_flows:
                implicit_flows.append(flow)

    initialized_dup1 = initialized.copy()
    pending_dup1 = pending.copy()
    body_flows = list()
    for node in body:
        body_flows += analyze_type(node, vuln, implicit, implicit_flows, pending_dup1, initialized_dup1, new_level)

    initialized_dup2 = initialized.copy()
    pending_dup2 = pending.copy()
    orelse_flows = list()
    for node in orelse:
        orelse_flows += analyze_type(node, vuln, implicit, implicit_flows, pending_dup2, initialized_dup2, new_level)

    intersection = [e for e in initialized_dup1 if e in initialized_dup2]
    for d in intersection:
        for var, lvl in d.items():
            fake_entry = {var: level}
            if fake_entry not in initialized:
                initialized.append({var: level})

    initialized_dups = initialized_dup1 + initialized_dup2 + initialized
    unique_initialized = list()
    for d in initialized_dups:
        if d not in unique_initialized:
            unique_initialized.append(d)

    pending_dups = pending_dup1 + pending_dup2
    lst_dups = list(set(pending_dups))
    new_pending = list(set(pending + lst_dups))

    initialized.clear()
    initialized += unique_initialized

    pending.clear()
    pending += new_pending

    unique_flows = list(set(body_flows + orelse_flows + test_flows))
    return unique_flows


def analyze_compare(comp_dict, vuln, implicit, implicit_flows, pending, initialized, level):
    comparators_list = comp_dict['comparators']
    left = comp_dict['left']
    comparators_flows = list()

    left_flows = analyze_type(left, vuln, implicit, implicit_flows, pending, initialized, level)

    for comparator in comparators_list:
        flow = analyze_type(comparator['comparator'], vuln, implicit, implicit_flows, pending, initialized, level)
        if not isinstance(flow, list):
            comparators_flows.append(flow)
        else:
            comparators_flows += flow

    flows = left_flows + comparators_flows
    return flows


def analyze_binop(bin_dict, vuln, implicit, implicit_flows, pending, initialized, level):
    left = bin_dict['left']
    right = bin_dict['right']

    left_flows = analyze_type(left, vuln, implicit, implicit_flows, pending, initialized, level)
    right_flows = analyze_type(right, vuln, implicit, implicit_flows, pending, initialized, level)

    flows = left_flows + right_flows
    return flows


def analyze_name(name_dict, new_flows, vuln, implicit, implicit_flows, pending, initialized, level):
    ctx = name_dict['ctx']
    name = name_dict['id']

    if initialized:
        name_entries = list(filter(lambda entry: name in entry.keys(), initialized))
        name_values = [d[name] for d in name_entries if d[name] <= level]
    else:
        name_values = list()

    if name in vuln['sources'] or (ctx == "Load" and not name_values):
        imp_str = "yes" if implicit else "no"
        new_flow = Flow(source=name, sink="", var="", sanitizer=[], implicit=imp_str, tainted=True)
        new_flows.append(new_flow)

    for pending_flow in pending:
        if pending_flow.var == name:
            dup_flow = Flow(source=pending_flow.source,
                            sink=pending_flow.sink,
                            var=pending_flow.var,
                            sanitizer=pending_flow.sanitizer.copy(),
                            implicit=pending_flow.implicit,
                            tainted=pending_flow.tainted)
            new_flows.append(dup_flow)


def analyze_assign(ass_dict, vuln, implicit, implicit_flows, pending, initialized, level):
    targets = ass_dict['targets']
    value = ass_dict['value']
    flows = analyze_type(value, vuln, implicit, implicit_flows, pending, initialized, level)
    vuln_sinks = vuln['sinks']
    flows_final = list()
    id_list = list()

    for target in targets:
        if "Name" in target.keys():
            id_list.append(target['Name']['id'])
        elif "Attribute" in target.keys():
            id_str = getID(target['Attribute'])
            id_list = id_str.split(".")

        for id in id_list:
            name_entries = list(filter(lambda entry: id in entry.keys() and entry[id] > level, initialized))
            for entry in name_entries:
                initialized.remove(entry)
            initialized.append({id: level})

            for pending_f in list(pending):
                if pending_f.var == id:
                    pending.remove(pending_f)

            if implicit:
                for imp_flow in implicit_flows:
                    new_pending_flow = Flow(source=imp_flow.source,
                                            sink="",
                                            var=id,
                                            sanitizer=imp_flow.sanitizer.copy(),
                                            implicit=imp_flow.implicit,
                                            tainted=imp_flow.tainted)
                    pending.append(new_pending_flow)

    for flow in flows:
        if flow.sink:
            flow_dup = Flow(source=flow.source, sink=flow.sink, var=flow.var, sanitizer=flow.sanitizer.copy(),
                            implicit=flow.implicit,
                            tainted=flow.tainted)
            flows_final.append(flow_dup)

        for target in targets:
            sink_var_flows = list()
            if "Name" in target.keys():
                id_list.append(target['Name']['id'])
            elif "Attribute" in target.keys():
                id_str = getID(target['Attribute'])
                id_list = id_str.split(".")

            for id in id_list:
                if id in vuln_sinks:
                    flow_dup = Flow(source=flow.source, sink=id, var="", sanitizer=flow.sanitizer.copy(),
                                    implicit=flow.implicit,
                                    tainted=flow.tainted)
                    sink_var_flows.append(flow_dup)
                    pending.append(flow_dup)

                flow2_dup = Flow(source=flow.source, sink="", var=id, sanitizer=flow.sanitizer.copy(),
                                 implicit=flow.implicit, tainted=flow.tainted)
                sink_var_flows.append(flow2_dup)
                pending.append(flow2_dup)
                flows_final += sink_var_flows

    return flows_final


def analyze_call(call_dict, vuln, implicit, implicit_flows, pending, initialized, level):
    args = call_dict['args']
    func_name = call_dict['func']['Name']['id']
    result = list()

    for arg in args:
        res = analyze_type(arg, vuln, implicit, implicit_flows, pending, initialized, level)
        if res:
            result += res

    vuln_sources = vuln['sources']
    vuln_sanitizers = vuln['sanitizers']
    vuln_sinks = vuln['sinks']

    if func_name in vuln_sources:
        imp_str = "yes" if implicit else "no"
        flow = Flow(source=func_name, sink="", var="", sanitizer=[], implicit=imp_str, tainted=True)
        result.append(flow)
    elif func_name in vuln_sanitizers:
        for fl in result:
            if not fl.sink and func_name not in fl.sanitizer:
                fl.sanitizer.append(func_name)
                fl.tainted = False
    elif func_name in vuln_sinks:
        for fl in result:
            fl.sink = func_name

    return result


def analyze(vuln, slice, implicit):
    flows = list()
    implicit_flows = list()
    for line in slice:
        result = analyze_type(line, vuln, implicit, implicit_flows, _pending_flows, _initialized_vars, level=0)
        for possible_flow in result:
            if possible_flow.sink:
                flows.append(possible_flow)

    return flows


def treat_result(flows, vuln):
    output = []
    vuln_name = vuln['vulnerability']
    idx = 1
    for flow in flows:
        f_source = flow.source
        f_sink = flow.sink
        f_sanitizers = flow.sanitizer.copy()

        if f_sanitizers:
            out_sanitizers = [f_sanitizers.copy()]
        else:
            out_sanitizers = []

        if not output:
            vl_name = f"{vuln_name}_{idx}"
            tainted_str = "yes" if flow.tainted else "no"
            new_dict = {"vulnerability": vl_name,
                        "source": f_source,
                        "sink": f_sink,
                        "unsanitized flows": tainted_str,
                        "sanitized flows": out_sanitizers
                        }
            output.append(new_dict)
        else:
            match = False
            for d in output:
                d_source = d['source']
                if d_source == f_source:
                    d_sink = d['sink']
                    if d_sink == f_sink:
                        f_sanitizers.sort()
                        for x in d['sanitized flows']:
                            x.sort()
                        if f_sanitizers and f_sanitizers not in d['sanitized flows']:
                            d['sanitized flows'].append(f_sanitizers)
                        if flow.tainted:
                            d['unsanitized flows'] = "yes"
                        match = True
                        break

            if not match:
                idx += 1
                vl_name = f"{vuln_name}_{idx}"
                tainted_str = "yes" if flow.tainted else "no"
                new_dict = {"vulnerability": vl_name,
                            "source": f_source,
                            "sink": f_sink,
                            "unsanitized flows": tainted_str,
                            "sanitized flows": out_sanitizers
                            }
                output.append(new_dict)

    return output


_pending_flows = []
_initialized_vars = []


@dataclass
class Flow:
    source: str
    sink: str
    var: str
    sanitizer: list
    implicit: str
    tainted: bool

    def __eq__(self, other):
        if isinstance(other, Flow):
            self.sanitizer.sort()
            other.sanitizer.sort()
            return self.source == other.source and \
                   self.sink == other.sink and \
                   self.var == other.var and \
                   self.sanitizer == other.sanitizer and \
                   self.implicit == other.implicit and \
                   self.tainted == other.tainted

    def __hash__(self):
        return hash(('source', self.source,
                     'sink', self.sink,
                     'var', self.var,
                     'sanitizer', tuple(self.sanitizer),
                     'implicit', self.implicit,
                     'tainted', self.tainted))


if __name__ == "__main__":
    # f = open('data/if_else.json')
    with open(sys.argv[1], "r") as f:
        data = json.load(f)
    slice_list = list()

    for line in data['body']:
        type_ast = line['ast_type']
        parser = Parser()
        ast_parser = parser.check_type(line)
        clean_data = ast_parser.eval()

        slice = json.dumps(clean_data, indent=2)
        slice_list.append(clean_data)

    with open(sys.argv[2], "r") as f:
        vulnerabilities = json.load(f)

    output = list()
    for vuln in vulnerabilities:
        simplicit = vuln['implicit']
        implicit = True if simplicit == "yes" else False
        result = analyze(vuln, slice_list, implicit)
        vuln_output = treat_result(result, vuln)
        output += vuln_output
        _pending_flows.clear()
        _initialized_vars.clear()

    filename = sys.argv[1].replace("data/", "")
    filename = filename.replace("examples/", "")
    filename = filename.replace(".json", ".output.json")
    with open(f"outputs/{filename}", "w") as f_out:
        json.dump(output, f_out)
