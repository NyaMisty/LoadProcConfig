//
// LoadProcConfig.cpp
// Load Processor Config
//
// Created by Alexander Hude on 31/03/16.
// Copyright (c) 2017 Alexander Hude. All rights reserved.
//

#ifdef __GNUC__
#pragma GCC diagnostic push
#endif
#ifdef _MSC_VER
# pragma warning(push, 0)
#endif

#include <ida.hpp>
#include <idp.hpp>
#include <loader.hpp>
#include <auto.hpp>

#include <name.hpp>
#include <offset.hpp>
#include <diskio.hpp>

#ifdef __GNUC__
#pragma GCC diagnostic popo
#endif
#ifdef _MSC_VER
# pragma warning(pop)
#endif

char cfgfile[QMAXFILE];

#ifdef _WIN32
	char dir_sep = '\\';
	char dir_up[] = "..\\";
#else
	char dir_sep = '/';
	char dir_up[] = "../";
#endif

//--------------------------------------------------------------------------

#define NO_GET_CFG_PATH

void init_cfg_filename(char *buf, size_t bufsize)
{
	buf[0] = '\0';

	int back_cnt = 0;
	size_t base_offset = 0;

	char* filename = ask_file(false, idadir(CFG_SUBDIR), "*.cfg", "Load Processor Configuration");

	if (nullptr == filename)
		return;

	// choose_ioport_device() only supports path relative to 'cfg' folder in IDA
	// therefore we need to generate it from our destination path

	// get 'cfg' path
	char cfg_path[QMAXFILE] = {0};
	qstrncpy(cfg_path, idadir(CFG_SUBDIR), QMAXFILE);

	// find common base and generate path to it from the source
	while (qstrstr(filename, cfg_path) == nullptr)
	{
		char* slash_pos = qstrrchr(cfg_path, dir_sep);
		if (slash_pos == nullptr)
			break;

		qstrncat(buf, dir_up, bufsize);
		slash_pos[0] = 0;
		back_cnt++;
	}
	base_offset = strlen(cfg_path);

	// create relative path to destination
	qstrncat(buf, filename + base_offset + 1, bufsize); // exclude left '/' from path
}

// include IO common routines (such as set_device_name, apply_config_file, etc..)
#include <iohandler.hpp>

// The netnode helper.
// Using this node we will save current configuration information in the IDA database.
static netnode helper;

struct stub_iohandler_t : public iohandler_t {
	stub_iohandler_t(netnode &nn) : iohandler_t(nn) {}
	void get_cfg_filename(char *buf, size_t bufsize) override {
		qstrncpy(buf, cfgfile, bufsize);
	}
	
};

stub_iohandler_t ioh(helper);

bool run(size_t)
{
	init_cfg_filename(cfgfile, QMAXFILE);
	
	if (strlen(cfgfile) == 0)
		return false;
	
	msg("ProcConf: loading config \"%s\"...\n", cfgfile);
	
	if ( choose_ioport_device(&ioh.device, cfgfile, NULL) )
	{
		msg("ProcConf: ... done\n");
		if (qstrcmp(ioh.device.c_str(), NONEPROC) != 0)
		{
			msg("ProcConf: device chosen \"%s\"\n", ioh.device.c_str());
			
			int resp_info = IORESP_ALL;
			ioh.display_infotype_dialog(IORESP_ALL, &resp_info, cfgfile);
			
			ioh.set_device_name(ioh.device.c_str(), resp_info);
			plan_range(0, BADADDR); // reanalyze program
		}
	}
	else
	{
		msg("ProcConf: ... failed\n");
	}
	
	return true;
}

//--------------------------------------------------------------------------

const ioport_t *find_sym(ea_t address)
{
	return find_ioport(ioh.ports, address);
}

ssize_t idaapi hook(void* user_data, int notification_code, va_list va)
{
	switch (notification_code) {
		case processor_t::ev_out_operand:
		{
			outctx_t* ctx = va_arg(va, outctx_t *);
			op_t* op = va_arg(va, op_t *);
			if (op->type == o_imm)
			{
				const ioport_t * port = find_sym(op->value);
				if ( port != NULL )
				{
					ctx->out_line(port->name.c_str(), COLOR_IMPNAME);
					return 1;
				}
			}
			break;
		}
		default:
			break;
	}

	return 0;
}

//--------------------------------------------------------------------------
plugmod_t *init(void)
{
  hook_to_notification_point(HT_IDP, hook, NULL);

#define PLUGIN_OK    ((plugmod_t *)1) ///< Plugin agrees to work with the current database.
                                      ///< It will be loaded as soon as the user presses the hotkey
#define PLUGIN_KEEP  ((plugmod_t *)2) ///< Plugin agrees to work with the current database and wants to stay in the memory
  return PLUGIN_OK;
}

//--------------------------------------------------------------------------
void term(void)
{
  unhook_from_notification_point(HT_IDP, hook, NULL);
}

//--------------------------------------------------------------------------
char help[] = "Load Processor Config";
char comment[] = "This module allows to load processor configuration files";
char wanted_name[] = "Load Processor Config";
char wanted_hotkey[] = "";


//--------------------------------------------------------------------------
//
//      PLUGIN DESCRIPTION BLOCK
//
//--------------------------------------------------------------------------
plugin_t PLUGIN =
{
  IDP_INTERFACE_VERSION,
  PLUGIN_PROC,          // plugin flags
  init,                 // initialize

  term,                 // terminate. this pointer may be NULL.

  run,                  // invoke plugin

  comment,              // long comment about the plugin
                        // it could appear in the status line
                        // or as a hint

  help,                 // multiline help about the plugin

  wanted_name,          // the preferred short name of the plugin
  wanted_hotkey         // the preferred hotkey to run the plugin
};
