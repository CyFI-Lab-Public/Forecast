class FunctionList:
    dic = {'fucntion_name': 'function_name'}
    def add(the_name: str, the_list :dict = dic):
        if the_name in the_list.keys():
            return
        else:
            the_list[the_name] = the_name
            return
