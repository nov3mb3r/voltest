from volatility.framework import interfaces

class DllList(interfaces.plugins.PluginInterface):
	"""GG baby"""

	@classmethod
	def get_requirements(cls):
	    return [requirements.TranslationLayerRequirement(name = 'primary',
		                                             description = 'Memory layer for the kernel',
		                                             architectures = ["Intel32", "Intel64"]),
		    requirements.SymbolTableRequirement(name = "nt_symbols",
		                                        description = "Windows kernel symbols"),
		    requirements.PluginRequirement(name = 'pslist',
		                                   plugin = pslist.PsList,
		                                   version = (1, 0, 0)),
		    requirements.ListRequirement(name = 'pid',
		                                 element_type = int,
		                                 description = "Process IDs to include (all other processes are excluded)",
		                                 optional = True)]

	def run(self):

	    filter_func = pslist.PsList.create_pid_filter(self.config.get('pid', None))

	    return renderers.TreeGrid([("PID", int),
		                       ("Process", str),
		                       ("Base", format_hints.Hex),
		                       ("Size", format_hints.Hex),
		                       ("Name", str),
		                       ("Path", str)],
		                      self._generator(pslist.PsList.list_processes(self.context,
		                                                                   self.config['primary'],
		                                                                   self.config['nt_symbols'],
		                                                                   filter_func = filter_func)))


	def _generator(self, procs):
		for proc in procs:
			for entry in proc.load_order_modules():
				BaseDllName = FullDllName = renderers.UnreadableValue()
				try:
					BaseDllName = entry.BaseDllName.get_string()
					# We assume that if the BaseDllName points to an invalid buffer, so will FullDllName
					FullDllName = entry.FullDllName.get_string()
				except exceptions.InvalidAddressException:
					pass
				yield (0, (proc.UniqueProcessId,
		               proc.ImageFileName.cast("string", max_length = proc.ImageFileName.vol.count,
		                                       errors = 'replace'),
		               format_hints.Hex(entry.DllBase), format_hints.Hex(entry.SizeOfImage),
		               BaseDllName, FullDllName))
