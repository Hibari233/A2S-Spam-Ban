/****************************************************************************************************
	[ANY?] A2S Anti Spam
*****************************************************************************************************

*****************************************************************************************************
	CHANGELOG: 
			0.1 - Initial Release.
			0.2 - SMRcon is now required.
			0.3 - Fix error / crash when removing ban.
			0.4 - 
				- Make SMRcon Optional.
				- Use .FindString method instead to check if IP banned or Whitelisted.
					
*****************************************************************************************************

*****************************************************************************************************
	INCLUDES.
*****************************************************************************************************/
#include <regex>
#include <PTaH>
#include <autoexecconfig>

#undef REQUIRE_EXTENSIONS
#tryinclude <smrcon>

/****************************************************************************************************
	ETIQUETTE.
*****************************************************************************************************/
#pragma newdecls required
#pragma semicolon 1

/****************************************************************************************************
	HANDLES.
*****************************************************************************************************/
Regex g_hRegexMatch = null;
ArrayList g_alWhiteList = null;
ArrayList g_alBannedIPs = null;
ConVar g_hCvarA2SBanTime = null;

/****************************************************************************************************
	INTS.
*****************************************************************************************************/
int g_iBanTime = 0;

/****************************************************************************************************
	STRINGS.
*****************************************************************************************************/
char g_szLogFile[PLATFORM_MAX_PATH];

public Plugin myinfo = 
{
	name = "A2S Anti Spam", 
	author = "SM9();", 
	version = "0.4", 
	url = "www.fragdeluxe.com"
}

public void OnPluginStart()
{
	PTaH(PTaH_ServerConsolePrint, Hook, ServerConsolePrint);
	
	g_hRegexMatch = CompileRegex("\\b(?:[0-9]{1,3}\\.){3}[0-9]{1,3}\\b");
	
	AutoExecConfig_SetFile("plugin.a2santispam");
	
	g_hCvarA2SBanTime = AutoExecConfig_CreateConVar("sm_a2s_bantime", "5", "The time an A2S spammer should get banned for");
	g_hCvarA2SBanTime.AddChangeHook(OnCvarChanged);
	AutoExecConfig_CleanFile(); AutoExecConfig_ExecuteFile();
	
	RegAdminCmd("sm_a2s_reload", Command_Reload, ADMFLAG_CONVARS, "Reloads A2S whitelist");
	BuildPath(Path_SM, g_szLogFile, sizeof(g_szLogFile), "logs/A2S-Ban.log");
	
	LoadA2SWhiteList();
	
	if (g_alBannedIPs != null) {
		g_alBannedIPs.Clear();
	} else {
		g_alBannedIPs = new ArrayList(45);
	}
}

public void OnConfigsExecuted() {
	FindConVar("sv_hibernate_when_empty").IntValue = 0; // Not sure if this fixes timers on empty servers but just incase.
	g_iBanTime = g_hCvarA2SBanTime.IntValue;
}

public void OnPluginEnd() {
	PTaH(PTaH_ServerConsolePrint, UnHook, ServerConsolePrint);
}

public Action Command_Reload(int iClient, int iArgs)
{
	if (LoadA2SWhiteList()) {
		ReplyToCommand(iClient, "A2S whitelist reloaded.");
	} else {
		ReplyToCommand(iClient, "A2S whitelist reload failed, please make sure file exists and is not corrupt.");
	}
	
	return Plugin_Handled;
}

public void OnCvarChanged(ConVar hConVar, const char[] szOldValue, const char[] szNewValue)
{
	if (hConVar == g_hCvarA2SBanTime) {
		g_iBanTime = StringToInt(szNewValue);
	}
}

public Action ServerConsolePrint(const char[] sMessage)
{
	if (StrContains(sMessage, "IP rate limiting client") == -1) {
		return Plugin_Continue;
	}
	
	char szIP[45]; strcopy(szIP, sizeof(szIP), sMessage);
	
	if (!ConvertToIPV4(szIP, 45)) {
		return Plugin_Continue;
	}
	
	if (g_alWhiteList.FindString(szIP) != -1 ||  g_alBannedIPs.FindString(szIP) != -1) {
		return Plugin_Continue;
	}
	
	CreateTimer(g_iBanTime * 60.0, Timer_RemoveBan, g_alBannedIPs.PushString(szIP));
	
	BanIdentity(szIP, 0, BANFLAG_IP, "A2S Query Spam");
	LogToFileEx(g_szLogFile, "%s was IP banned for %d minute(s) (A2S query spam)", szIP, g_iBanTime);
	
	return Plugin_Continue;
}

public Action Timer_RemoveBan(Handle hTimer, int iArrayCell)
{
	if (g_alBannedIPs.Length < iArrayCell) {
		return Plugin_Stop;
	}
	
	char szIP[45]; g_alBannedIPs.GetString(iArrayCell, szIP, sizeof(szIP));
	
	RemoveBan(szIP, BANFLAG_IP);
	g_alBannedIPs.Erase(iArrayCell);
	LogToFileEx(g_szLogFile, "%s was unbanned.", szIP);
	
	return Plugin_Stop;
}

#if defined _updater_included
public Action SMRCon_OnAuth(int iRconId, const char[] szIP, const char[] szPassword, bool &bAllow)
{
	if(g_alBannedIPs.FindString(szIP) != -1) {
		bAllow = false;
		return Plugin_Changed;
	}
	
	return Plugin_Continue;
}

public Action SMRCon_OnCommand(int iRconId, const char[] szIP, const char[] szCommand, bool &bAllow)
{
	if(g_alBannedIPs.FindString(szIP) != -1) {
		bAllow = false;
		return Plugin_Changed;
	}
	
	return Plugin_Continue;
}
#endif

stock bool LoadA2SWhiteList()
{
	if (g_alWhiteList != null) {
		g_alWhiteList.Clear();
	} else {
		g_alWhiteList = new ArrayList(45);
	}
	
	char szPath[PLATFORM_MAX_PATH];
	BuildPath(Path_SM, szPath, sizeof(szPath), "configs/a2s-whitelist.txt");
	
	if (!FileExists(szPath)) {
		return false;
	}
	
	KeyValues hKv = new KeyValues("A2S Whitelist");
	
	if (!hKv.ImportFromFile(szPath)) {
		return false;
	}
	
	hKv.GotoFirstSubKey();
	
	char szBuffer[45];
	do {
		hKv.GetString("ip", szBuffer, sizeof(szBuffer));
		
		if (!ConvertToIPV4(szBuffer, sizeof(szBuffer))) {
			continue;
		}
		
		if (g_alWhiteList.FindString(szBuffer) != -1) {
			continue;
		}
		
		g_alWhiteList.PushString(szBuffer);
		
	} while (hKv.GotoNextKey());
	
	delete hKv;
	
	return true;
}

stock bool ConvertToIPV4(char[] szReturn, int iLength)
{
	int iMatches = g_hRegexMatch.Match(szReturn);
	
	for (int i = 0; i < iMatches; i++) {
		if (g_hRegexMatch.GetSubString(i, szReturn, iLength)) {
			return true;
		}
	}
	
	if (StrContains(szReturn, "IP rate limiting client") != -1) {
		return false;
	}
	
	AddrInfo aiAddress; TrimString(szReturn); StripQuotes(szReturn);
	
	if (PTaH_GetAddrInfo(szReturn, AF_INET, aiAddress) == 0) {
		aiAddress.GetIP(szReturn, iLength);
		aiAddress.ClearMem();
		return true;
	}
	
	return false;
}