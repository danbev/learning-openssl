### Errors in OpenSSL

Each thread has a thread local struct which look like this:
```c
#define ERR_NUM_ERRORS  16                                                       

struct err_state_st {                                                              
    int err_flags[ERR_NUM_ERRORS];                                                 
    unsigned long err_buffer[ERR_NUM_ERRORS];                                      
    char *err_data[ERR_NUM_ERRORS];                                                
    size_t err_data_size[ERR_NUM_ERRORS];                                          
    int err_data_flags[ERR_NUM_ERRORS];                                            
    const char *err_file[ERR_NUM_ERRORS];                                          
    int err_line[ERR_NUM_ERRORS];                                                  
    const char *err_func[ERR_NUM_ERRORS];                                          
    int top, bottom;                                                            
};                                                                              
# endif
```
So there can be a maximum of 16 errors. And each error can have flags. 

```c
  ERR_STATE *es;
  int top;

  es = err_get_state_int();
```
`err_get_state_int` will get the thread local struct or create a new one
if one does not already exist.

### Raising/Setting an error
This is done using one of the `ERR_raise` macros:
```c
# define ERR_raise(lib, reason) ERR_raise_data((lib),(reason),NULL)
# define ERR_raise_data                                         \
    (ERR_new(),                                                 \
     ERR_set_debug(OPENSSL_FILE,OPENSSL_LINE,OPENSSL_FUNC),     \
     ERR_set_error)
```
And this would be used like this:
```c
    ERR_raise_data(example_lib, reason_1, "after setting mark");
```
Which would get expanded by the preprocessor as:
```console
$ make err_pre
```
```c
(ERR_new(), ERR_set_debug("err.c",45,__func__), ERR_set_error)(example_lib, reason_1, "after setting mark");
```
ERR_new will find an entry at the top of the error queue and clear that entry.
ERR_set_debug will then add to that entry, as will ERR_set_error. This syntax
migth look odd if you have not seen it before but is
[legal](https://github.com/danbev/learning-c/blob/master/comma.c) and just think
of it as:
```c
  ERR_new();
  ERR_set_debug("err.c",45,__func__);
  ERR_set_error(example_lib, reason_1, "after setting mark");
```



