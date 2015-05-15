from distutils.core import setup,Extension
import os

projdir = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))

libdir = os.path.join(projdir, "lib/.libs")
incdir = os.path.join(projdir, "lib")

setup(name='pyknc',
      version='.5',
      ext_modules=[Extension('pyknc',
                             library_dirs=[libdir,],
                             include_dirs=[incdir,],
                             sources = ['pyknc.c'],
                             libraries = ['knc'] ),
	    ],

	)
