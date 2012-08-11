import inspect

def return_func_name():
    """Returns name of calling function."""
    return inspect.stack()[1][3]
