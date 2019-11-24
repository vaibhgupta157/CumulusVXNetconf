# -*- coding: utf-8 -*-
from operator import attrgetter
from pyangbind.lib.yangtypes import RestrictedPrecisionDecimalType
from pyangbind.lib.yangtypes import RestrictedClassType
from pyangbind.lib.yangtypes import TypedListType
from pyangbind.lib.yangtypes import YANGBool
from pyangbind.lib.yangtypes import YANGListType
from pyangbind.lib.yangtypes import YANGDynClass
from pyangbind.lib.yangtypes import ReferenceType
from pyangbind.lib.base import PybindBase
from collections import OrderedDict
from decimal import Decimal
from bitarray import bitarray
import six

# PY3 support of some PY2 keywords (needs improved)
if six.PY3:
  import builtins as __builtin__
  long = int
elif six.PY2:
  import __builtin__

class yc_commands_cumulus_nclu__commands(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module cumulus-nclu - based on the path /commands. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.
  """
  __slots__ = ('_path_helper', '_extmethods', '__cmd',)

  _yang_name = 'commands'

  _yang_namespace = 'http://example.com/cumulus-nclu'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__cmd = YANGDynClass(unique=True, base=TypedListType(allowed_type=six.text_type), is_leaf=False, yang_name="cmd", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=True, namespace='http://example.com/cumulus-nclu', defining_module='cumulus-nclu', yang_type='string', is_config=True)

    load = kwargs.pop("load", None)
    if args:
      if len(args) > 1:
        raise TypeError("cannot create a YANG container with >1 argument")
      all_attr = True
      for e in self._pyangbind_elements:
        if not hasattr(args[0], e):
          all_attr = False
          break
      if not all_attr:
        raise ValueError("Supplied object did not have the correct attributes")
      for e in self._pyangbind_elements:
        nobj = getattr(args[0], e)
        if nobj._changed() is False:
          continue
        setmethod = getattr(self, "_set_%s" % e)
        if load is None:
          setmethod(getattr(args[0], e))
        else:
          setmethod(getattr(args[0], e), load=load)

  def _path(self):
    if hasattr(self, "_parent"):
      return self._parent._path()+[self._yang_name]
    else:
      return [u'commands']

  def _get_cmd(self):
    """
    Getter method for cmd, mapped from YANG variable /commands/cmd (string)
    """
    return self.__cmd
      
  def _set_cmd(self, v, load=False):
    """
    Setter method for cmd, mapped from YANG variable /commands/cmd (string)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_cmd is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_cmd() directly.
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,unique=True, base=TypedListType(allowed_type=six.text_type), is_leaf=False, yang_name="cmd", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=True, namespace='http://example.com/cumulus-nclu', defining_module='cumulus-nclu', yang_type='string', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """cmd must be of a type compatible with string""",
          'defined-type': "string",
          'generated-type': """YANGDynClass(unique=True, base=TypedListType(allowed_type=six.text_type), is_leaf=False, yang_name="cmd", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=True, namespace='http://example.com/cumulus-nclu', defining_module='cumulus-nclu', yang_type='string', is_config=True)""",
        })

    self.__cmd = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_cmd(self):
    self.__cmd = YANGDynClass(unique=True, base=TypedListType(allowed_type=six.text_type), is_leaf=False, yang_name="cmd", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=True, namespace='http://example.com/cumulus-nclu', defining_module='cumulus-nclu', yang_type='string', is_config=True)

  cmd = __builtin__.property(_get_cmd, _set_cmd)


  _pyangbind_elements = OrderedDict([('cmd', cmd), ])


class cumulus_nclu(PybindBase):
  """
  This class was auto-generated by the PythonClass plugin for PYANG
  from YANG module cumulus-nclu - based on the path /cumulus-nclu. Each member element of
  the container is represented as a class variable - with a specific
  YANG type.
  """
  __slots__ = ('_path_helper', '_extmethods', '__commands',)

  _yang_name = 'cumulus-nclu'

  _pybind_generated_by = 'container'

  def __init__(self, *args, **kwargs):

    self._path_helper = False

    self._extmethods = False
    self.__commands = YANGDynClass(base=yc_commands_cumulus_nclu__commands, is_container='container', yang_name="commands", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=True, extensions=None, namespace='http://example.com/cumulus-nclu', defining_module='cumulus-nclu', yang_type='container', is_config=True)

    load = kwargs.pop("load", None)
    if args:
      if len(args) > 1:
        raise TypeError("cannot create a YANG container with >1 argument")
      all_attr = True
      for e in self._pyangbind_elements:
        if not hasattr(args[0], e):
          all_attr = False
          break
      if not all_attr:
        raise ValueError("Supplied object did not have the correct attributes")
      for e in self._pyangbind_elements:
        nobj = getattr(args[0], e)
        if nobj._changed() is False:
          continue
        setmethod = getattr(self, "_set_%s" % e)
        if load is None:
          setmethod(getattr(args[0], e))
        else:
          setmethod(getattr(args[0], e), load=load)

  def _path(self):
    if hasattr(self, "_parent"):
      return self._parent._path()+[self._yang_name]
    else:
      return []

  def _get_commands(self):
    """
    Getter method for commands, mapped from YANG variable /commands (container)
    """
    return self.__commands
      
  def _set_commands(self, v, load=False):
    """
    Setter method for commands, mapped from YANG variable /commands (container)
    If this variable is read-only (config: false) in the
    source YANG file, then _set_commands is considered as a private
    method. Backends looking to populate this variable should
    do so via calling thisObj._set_commands() directly.
    """
    if hasattr(v, "_utype"):
      v = v._utype(v)
    try:
      t = YANGDynClass(v,base=yc_commands_cumulus_nclu__commands, is_container='container', yang_name="commands", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=True, extensions=None, namespace='http://example.com/cumulus-nclu', defining_module='cumulus-nclu', yang_type='container', is_config=True)
    except (TypeError, ValueError):
      raise ValueError({
          'error-string': """commands must be of a type compatible with container""",
          'defined-type': "container",
          'generated-type': """YANGDynClass(base=yc_commands_cumulus_nclu__commands, is_container='container', yang_name="commands", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=True, extensions=None, namespace='http://example.com/cumulus-nclu', defining_module='cumulus-nclu', yang_type='container', is_config=True)""",
        })

    self.__commands = t
    if hasattr(self, '_set'):
      self._set()

  def _unset_commands(self):
    self.__commands = YANGDynClass(base=yc_commands_cumulus_nclu__commands, is_container='container', yang_name="commands", parent=self, path_helper=self._path_helper, extmethods=self._extmethods, register_paths=True, extensions=None, namespace='http://example.com/cumulus-nclu', defining_module='cumulus-nclu', yang_type='container', is_config=True)

  commands = __builtin__.property(_get_commands, _set_commands)


  _pyangbind_elements = OrderedDict([('commands', commands), ])

