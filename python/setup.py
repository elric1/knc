from distutils.core import setup,Extension
import os

libdir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "lib"))
incdir = os.path.normpath(os.path.join(os.path.dirname(__file__), "..", "include"))

setup(name='pyknc',
      version='.5',
      ext_modules=[Extension('pyknc',
                             library_dirs=[libdir,],
                             include_dirs=[incdir,],
                             sources = ['pyknc.c'],
                             libraries = ['knc'] ),
	    ],

	)


