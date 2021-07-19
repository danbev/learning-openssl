### buildtype error
This error has happend now and again, I think mostly after rebasing
the working branch I've got for statically linking
[OpenSSL 3.0](https://github.com/danbev/node/tree/openssl-3.0-statically-linked):
```console
+ exec ./configure --openssl-is-fips
Traceback (most recent call last):
  File "/home/danielbevenius/work/nodejs/openssl/tools/gyp_node.py", line 55, in <module>
    run_gyp(sys.argv[1:])
  File "/home/danielbevenius/work/nodejs/openssl/tools/gyp_node.py", line 48, in run_gyp
    rc = gyp.main(args)
  File "/home/danielbevenius/work/nodejs/openssl/tools/gyp/pylib/gyp/__init__.py", line 658, in main
    return gyp_main(args)
  File "/home/danielbevenius/work/nodejs/openssl/tools/gyp/pylib/gyp/__init__.py", line 625, in gyp_main
    [generator, flat_list, targets, data] = Load(
  File "/home/danielbevenius/work/nodejs/openssl/tools/gyp/pylib/gyp/__init__.py", line 108, in Load
    default_variables['buildtype']))
KeyError: 'buildtype'
make: *** [Makefile:150: out/Makefile] Error 1
```
I added the key `buildtype` when adding for absolue paths in gyp and this was
passed in via the configuration.py file:
```python
gyp_args = ['--no-parallel', '-Dconfiguring_node=1',                             
    '-Dbuildtype=' + output['target_defaults']['default_configuration']]; 
```
But this option is only pased when running configuration.py and not when the
Makefile target `out/Makefile`'s recipe runs tools/gyp_node.py. Removing this
and instead using `CONFIGURATION_NAME` should work:
```python
     default_variables.setdefault("PRODUCT_DIR_ABS", os.path.join(output_dir,     
         default_variables['CONFIGURATION_NAME']))
```
We can check this by touching config.gypi and then running:
```console
$ make -j8
```

When looking into this issue I noticed that tools/gyp_node.py used
config_fips.gypi which could be deleted now I think.
