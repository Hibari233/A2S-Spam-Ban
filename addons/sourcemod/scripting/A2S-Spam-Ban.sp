/****************************************************************************************************
	[ANY?] A2S Anti Spam
*****************************************************************************************************

*****************************************************************************************************
	CHANGELOG: 
			0.1 - Initial Release.
			0.2 - SMRcon is now required.
					
*****************************************************************************************************

*****************************************************************************************************
	INCLUDES.
*****************************************************************************************************/
#include <regex>
#include <PTaH>
#include <autoexecconfig>
#include <smrcon>

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
	version = "0.2", 
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
		g_alBannedIPs = new ArrayList(256);
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
	
	if (IsIPv4WhiteListed(szIP)) {
		return Plugin_Continue;
	}
	
	if (BanIdentity(szIP, g_iBanTime, BANFLAG_IP, "A2S Query Spam")) {
		LogToFileEx(g_szLogFile, "%s was IP banned for %d minute(s) (A2S query spam)", szIP, g_iBanTime);
		CreateTimer(g_iBanTime * 60.0, Timer_RemoveBan, g_alBannedIPs.PushString(szIP));
	}
	
	return Plugin_Continue;
}

public Action Timer_RemoveBan(Handle hTimer, int iArrayCell)
{
	if (g_alBannedIPs.Length < iArrayCell) {
		return Plugin_Stop;
	}
	
	char szIP[45]; g_alBannedIPs.GetString(iArrayCell, szIP, sizeof(szIP));
	
	g_alBannedIPs.Erase(iArrayCell);
	RemoveBan(szIP, BANFLAG_IP);
	LogToFileEx(g_szLogFile, "%s was unbanned.", szIP);
	
	return Plugin_Stop;
}

public Action SMRCon_OnAuth(int iRconId, const char[] szIP, const char[] szPassword, bool &bAllow)
{
	int iBanIPs = g_alBannedIPs.Length;
	
	if (iBanIPs <= 0) {
		return Plugin_Continue;
	}
	
	char szBuffer[45];
	
	for (int i = 0; i < iBanIPs; i++) {
		g_alBannedIPs.GetString(i, szBuffer, sizeof(szBuffer));
		
		if (StrEqual(szBuffer, szIP, false)) {
			bAllow = false;
			return Plugin_Changed;
		}
	}
	
	return Plugin_Continue;
}

public Action SMRCon_OnCommand(int iRconId, const char[] szIP, const char[] szCommand, bool &bAllow)
{
	int iBanIPs = g_alBannedIPs.Length;
	
	if (iBanIPs <= 0) {
		return Plugin_Continue;
	}
	
	char szBuffer[45];
	
	for (int i = 0; i < iBanIPs; i++) {
		g_alBannedIPs.GetString(i, szBuffer, sizeof(szBuffer));
		
		if (StrEqual(szBuffer, szIP, false)) {
			bAllow = false;
			return Plugin_Changed;
		}
	}
	
	return Plugin_Continue;
}

stock bool LoadA2SWhiteList()
{
	if (g_alWhiteList != null) {
		g_alWhiteList.Clear();
	} else {
		g_alWhiteList = new ArrayList(256);
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
		
		if (IsIPv4WhiteListed(szBuffer)) {
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

stock bool IsIPv4WhiteListed(const char[] szIP)
{
	int iAddresses = g_alWhiteList.Length;
	
	if (iAddresses <= 0) {
		return false;
	}
	
	char szBuffer[45];
	
	for (int i = 0; i < iAddresses; i++) {
		g_alWhiteList.GetString(i, szBuffer, sizeof(szBuffer));
		
		if (StrEqual(szIP, szBuffer, false)) {
			return true;
		}
	}
	
	return false;
} 