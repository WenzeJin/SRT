"""
    SVF report transformer (SRT)
    Created By: Wenze Jin
    Date: 1/17/2024

    对于已有的SVF报告，做以下工作:
    1. 保留现有的所有信息
    2. 将文件名转换为文件实际的绝对路径（因为SVF提供的报告中只能指出文件名，不便于定位实际的位置）
    3. 自动从缺陷警告位置获取可能的变量名
    4. 将缺陷附近的代码摘录
    5. 为每一条警报添加标签，反映其是否正确地被处理并生成中间格式

"""
import json
import pathlib
import argparse
import re

C_VAR_NAME = re.compile('[_a-zA-Z]+[_a-zA-Z0-9.\\[\\]]*')

C_CPP_KEYWORDS = {'auto', 'break', 'case', 'catch', 'char', 'const',
                  'continue', 'default', 'do', 'double', 'else',
                  'enum', 'extern', 'float', 'for', 'goto', 'if',
                  'int', 'long', 'register', 'return', 'short',
                  'signed', 'sizeof', 'static', 'struct', 'switch', 'try',
                  'typedef', 'union', 'unsigned', 'void', 'volatile', 'while', 'when'}
class SVFTag:
    # vanilla tags
    class DefectType:
        NF = "Never Free"
        DF = "Double Free"
        UAF = "Use After Free"
        PL = "Partial Leak"

    DT = "DefectType"
    Loc = "Location"
    l = "ln"
    c = "cl"
    f = "fl"
    Func = "Function"
    Des = "Description"
    CFP = "ConditionalFreePath"
    BL = "BranchLoc"
    BC = "BranchCond"
    true = "True"
    false = "False"
    E = "Events"
    # new tags
    Code = "CodeNear"
    Flag = "SuccessTransform"
    Msg = "TransformMessage"
    V = "Var"

class TransformMessage:
    AC = ""
    DFF = "Duplicated Files Found"
    NSF = "No Such File"
    CIV = "Cannot Infer VarName"
    DFFIC = "Duplicated Files Found In Conditions Analysis"
    NSFIC = "No Such File In Conditions Analysis"

def SRT_log(success:bool, msg:str, error:str= ""):
    if success:
        print("\033[32m[SRT]\033[0m " + msg)
    else:
        if error == "warning":
            print("\033[33m[SRT Warning]\033[0m " + msg)
        elif error == "fatal":
            print("\033[31m[SRT Fatal Error]\033[0m " + msg)
        else:
            print("\033[31m[SRT]\033[0m " + msg)

def deal_duplicate(ln:int, co:int, files:list[pathlib.Path], func_name:str="") -> tuple:
    res:list[pathlib.Path] = []
    for file in files:
        adir = file.absolute()
        with open(adir) as test_file:
            lines = test_file.readlines()
            if len(lines) < ln:
                continue
            if len(lines[ln - 1]) < co:
                continue
            if func_name:
                flag = False
                for line in lines[:ln]:
                    if func_name in line:
                        flag = True
                        break
                if not flag:
                    continue
            res.append(file)
    if len(res) > 1:
        return 1, None
    elif len(res) == 1:
        return 0, res[0]
    else:
        return -1, None

def are_all_letters_uppercase(s:str):
    letters = [char for char in s if char.isalpha()]
    return all(letter.isupper() for letter in letters)

def name_filter(lstr: str, it: iter, cap_assert:bool) -> list[str]:
    """
    用简易快速的办法过滤不可能是变量名的字符串
    1. 变量名周围不应有引号
    2. 变量名周围括号的存在应该合法
    3. 假设全大写字母名称为常量或者宏
    4. 排除C/C++关键字
    :param cap_assert: 假设全大写字母名称为常量或者宏
    :param lstr: 包含该字符串的代码行
    :param it: re.match 类型的 iter
    :return: 过滤后的字符串 list
    """
    res = []
    for name in it:
        start = name.start()
        end = name.end()
        if (lstr[max(0, start - 1)] == '\'' or lstr[max(0, start - 1)] == '\"'
                or lstr[min(len(lstr) - 1, end)] == '\'' or lstr[min(len(lstr) - 1, end)] == '\"'
                or lstr[max(0, start - 1)] == ')' or lstr[min(len(lstr) - 1, end)] == '(' ):
            continue
        if (lstr[start:end] not in res and lstr[start:end] not in C_CPP_KEYWORDS
                and (not are_all_letters_uppercase(lstr[start:end]) or not cap_assert)):
            res.append(lstr[start:end])
    return res


if __name__ == '__main__':
    # hello message
    SRT_log(True, "SVF Report Transformer")

    # set the args
    parser = argparse.ArgumentParser()
    parser.add_argument('--input_file', type=str,
                        default='in.json',
                        help='Set input json file directory. (It should be a svf report)')
    parser.add_argument('--output_file', type=str,
                        default='out.json',
                        help='Set output file directory.')
    parser.add_argument('--root_dir', type=str,
                        default='./',
                        help='Set the root directory of the source code.')
    parser.add_argument('--copy_range', type=int,
                        default=5,
                        help='Set the range of lines that will be copied around the line of warning.')
    parser.add_argument('--cap_not_name', type=bool,
                        default=True,
                        help='Assert if a name contains no lower characters, it is a const value or a macro.')

    # parse the args
    args = parser.parse_args()
    rdir = args.root_dir

    with open(args.input_file, 'r') as jsonf:
        report = json.load(jsonf)
        SRT_log(True, "Successfully loaded JSON file: " + str(args.input_file))
        SRT_log(True, f"There are {len(report)} warnings in this report.")
        cnt = -1
        for warn in report:
            cnt += 1
            # 0. 初始化要增加的key
            warn[SVFTag.V] = []
            warn[SVFTag.Code] = []
            warn[SVFTag.Flag] = ""
            warn[SVFTag.Msg] = ""



            # 1. 根据文件名生成实际相对路径
            svf_file:str = warn[SVFTag.Loc][SVFTag.f]
            pl:pathlib.Path = pathlib.Path()
            target_files = pl.rglob(svf_file)
            ori_path:list[pathlib.Path] = []
            src_file:pathlib.Path = pathlib.Path()
            for each in target_files:
                ori_path.append(each)
            if len(ori_path) == 1:
                warn[SVFTag.Loc][SVFTag.f] = str(ori_path[0])
                src_file = ori_path[0]
            elif len(ori_path) == 0:
                warn[SVFTag.Flag] = SVFTag.false
                warn[SVFTag.Msg] = TransformMessage.NSF
                SRT_log(False, f"Cannot find file path of file \"{svf_file}\" of warning {cnt}.", error="warning")
                continue
            else:

                flag, src_file = deal_duplicate(warn[SVFTag.Loc][SVFTag.l], warn[SVFTag.Loc][SVFTag.c], ori_path, warn[SVFTag.Func])
                if flag == 1:
                    warn[SVFTag.Flag] = SVFTag.false
                    warn[SVFTag.Msg] = TransformMessage.DFF
                    SRT_log(False, f"Find duplicated file path of file \"{svf_file}\" of warning {cnt}.",
                            error="warning")
                    continue
                elif flag == -1:
                    warn[SVFTag.Flag] = SVFTag.false
                    warn[SVFTag.Msg] = TransformMessage.NSF
                    SRT_log(False, f"Cannot find file path of file \"{svf_file}\" of warning {cnt}.", error="warning")
                    continue

            adir = str(src_file.absolute())
            with open(adir) as code_file:
                # 2. 推断变量名
                lines = code_file.readlines()
                l:int = warn[SVFTag.Loc][SVFTag.l]
                line = lines[l - 1]
                c = warn[SVFTag.Loc][SVFTag.c]
                name_iter = C_VAR_NAME.finditer(line)
                var_name:list[str] = name_filter(line, name_iter, args.cap_not_name)
                warn[SVFTag.V] = var_name

                # 3. 摘录附近行代码 在这里需要对PartialLeak的分支条件做更多的摘录
                lines = lines[max(0, l - 1 - args.copy_range):min(len(lines), l + args.copy_range)]
                lines = [line.lstrip().rstrip() for line in lines]
                warn[SVFTag.Code] = lines

                # 3.1 PartialLeak分支的特殊处理
                if warn[SVFTag.DT] == SVFTag.DefectType.PL:
                    conditional_paths = warn[SVFTag.Des][SVFTag.CFP]
                    for cond in conditional_paths:
                        l: int = cond[SVFTag.BL][SVFTag.l]
                        svf_file: str = cond[SVFTag.BL][SVFTag.f]
                        pl: pathlib.Path = pathlib.Path()
                        target_files = pl.rglob(svf_file)
                        ori_path: list[pathlib.Path] = []
                        src_file: pathlib.Path = pathlib.Path()
                        for each in target_files:
                            ori_path.append(each)
                        if len(ori_path) == 1:
                            cond[SVFTag.BL][SVFTag.f] = str(ori_path[0])
                            src_file = ori_path[0]
                        elif len(ori_path) == 0:
                            warn[SVFTag.Flag] = SVFTag.false
                            warn[SVFTag.Msg] = TransformMessage.NSF
                            SRT_log(False, f"Cannot find file path of file \"{svf_file}\" of warning {cnt} during conditional free path analysis.",
                                    error="warning")
                            continue
                        else:
                            flag, src_file = deal_duplicate(warn[SVFTag.Loc][SVFTag.l], warn[SVFTag.Loc][SVFTag.c],
                                                            ori_path)
                            if flag == 1:
                                warn[SVFTag.Flag] = SVFTag.false
                                warn[SVFTag.Msg] = TransformMessage.DFFIC
                                SRT_log(False, f"Find duplicated file path of file \"{svf_file}\" of warning {cnt} during conditional free ath analysis.",
                                        error="warning")
                                continue
                            elif flag == -1:
                                warn[SVFTag.Flag] = SVFTag.false
                                warn[SVFTag.Msg] = TransformMessage.NSFIC
                                SRT_log(False, f"Cannot find file path of file \"{svf_file}\" of warning {cnt} during conditional free ath analysis.",
                                        error="warning")
                                continue
                        adir = str(src_file.absolute())
                        with open(adir) as condition_file:
                            lines = condition_file.readlines()
                            cond[SVFTag.Code] = lines[l - 1].lstrip().rstrip()
            warn[SVFTag.Flag] = SVFTag.true
            warn[SVFTag.Msg] = TransformMessage.AC

        with open(args.output_file, 'w') as outf:
            json.dump(report, outf, indent=4)
            SRT_log(True, "Successfully dumped JSON output: " + str(args.output_file))

