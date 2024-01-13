#include"mainWindow.h"
#include"resource.h"

WCHAR g_FileName[MAX_PATH] = { 0 };

void set_icon(HWND hwnddlg) {
	HINSTANCE hInstance2 = ::GetModuleHandle(NULL);

	HICON hiconbig = LoadIcon(hInstance2, MAKEINTRESOURCE(IDI_ICON1));
	HICON hiconsmall = LoadIcon(hInstance2, MAKEINTRESOURCE(IDI_ICON1));
	SendMessage(hwnddlg, WM_SETICON, ICON_BIG, (LONG64)hiconbig);
	SendMessage(hwnddlg, WM_SETICON, ICON_SMALL, (LONG64)hiconsmall);
}


INT_PTR CALLBACK mainwindow(HWND hwnddlg, UINT umsg, WPARAM wparam, LPARAM lparam) {
	switch (umsg){
	case WM_INITDIALOG: {
		CheckDlgButton(hwnddlg, IDC_RADIO1, BST_CHECKED);
		CheckDlgButton(hwnddlg, IDC_RADIO3, BST_CHECKED);
		set_icon(hwnddlg);
		BOOL SS = ChangeWindowMessageFilter(WM_DROPFILES, MSGFLT_ADD);
		ChangeWindowMessageFilter(0x0049, MSGFLT_ADD);
		return FALSE;
	}
	case WM_CLOSE:
		EndDialog(hwnddlg, 0);
		return TRUE;
	case WM_SIZE:
		switch (wparam){
		case SIZE_MINIMIZED:
			//ShowWindow(hwnddlg, SW_HIDE);
			return FALSE;
		}
	case WM_DROPFILES:{
		HDROP hDrop = (HDROP)wparam;
		UINT fileCount = DragQueryFile(hDrop, 0xFFFFFFFF, NULL, 0);
		for (UINT i = 0; i < fileCount; i++) {

			DragQueryFile(hDrop, i, g_FileName, MAX_PATH);

			bool isexe = check_file_extensionW(g_FileName, L"exe");
			if (isexe) {
				SetWindowText(GetDlgItem(hwnddlg, IDC_EDIT1), g_FileName);
			}
			else {
				MessageBox(hwnddlg,L"The file suffix must be. exe", L"WARNING", MB_OK | MB_ICONEXCLAMATION);
				RtlZeroMemory(g_FileName,MAX_PATH*sizeof(WCHAR));
			}
		}
		DragFinish(hDrop);
		return TRUE;
	}
	case WM_COMMAND: {
		switch (LOWORD(wparam)){
		case IDC_BUTTON1: {
			OPENFILENAME stopenfilename = { 0 };
			TCHAR szpeFILEext[100] = L"*.exe";
			stopenfilename.lStructSize = sizeof(OPENFILENAME);
			stopenfilename.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
			stopenfilename.hwndOwner = hwnddlg;
			stopenfilename.lpstrFilter = szpeFILEext;
			stopenfilename.lpstrFile = g_FileName;
			stopenfilename.nMaxFile = MAX_PATH;
			GetOpenFileName(&stopenfilename);
			if (g_FileName[0] == NULL) {
				return FALSE;
			}
			bool isexe = check_file_extensionW(g_FileName, L"exe");
			if (!isexe) {
				MessageBox(hwnddlg, L"The file suffix must be. exe", L"WARNING", MB_OK | MB_ICONEXCLAMATION);
				RtlZeroMemory(g_FileName, MAX_PATH * sizeof(WCHAR));
				return FALSE;
			}
			SetWindowText(GetDlgItem(hwnddlg, IDC_EDIT1), L"");
			SetWindowText(GetDlgItem(hwnddlg, IDC_EDIT1),g_FileName);
			return FALSE;
		}
		case IDC_BUTTON2: {//run      to system

			if (g_FileName[0] == NULL) {
				MessageBox(hwnddlg, L"Please select a path or drag exe into the control", L"Tip", MB_OK);
				return FALSE;
			}
 			UINT checked = IsDlgButtonChecked(hwnddlg, IDC_RADIO1);
			if (checked == BST_CHECKED) {
				UINT checked2 = IsDlgButtonChecked(hwnddlg, IDC_RADIO3);
				if (checked2 == BST_CHECKED) {
					DWORD pid = getPidFromName(L"lsass.exe");
					CreateSystemFromParent(pid, g_FileName, NULL);
					return FALSE;
				}
				else {
					CreateSystemFromToken(g_FileName, NULL);
					return FALSE;
				}
				return FALSE;
			}
			else {    //run to trustedinstaller 
				UINT checked = IsDlgButtonChecked(hwnddlg, IDC_RADIO3);//from parent
				if (checked == BST_CHECKED) {
					CreateTrustedinstallerFromParent(g_FileName, NULL);
					return FALSE;
				}
				else {
					//MessageBox(hwnddlg, L"Cannot obtain trustedinstaller permission as a token", L"WARNING", MB_OK);
					CreateTrustedinstallerFromParent(g_FileName, NULL);
					return FALSE;
				}

			}
			return FALSE;
		}
		case IDC_BUTTON3: {
			EndDialog(hwnddlg, 0);
			return TRUE;
		}
		}
	}
	}
	return FALSE;
}

int WinMain(_In_ HINSTANCE hInstance, _In_opt_ HINSTANCE hPrevInstance, _In_ LPSTR lpCmdLine, _In_ int nShowCmd) {

	BOOL btn = EnablePrivilege(SE_DEBUG_NAME, TRUE);
	SetProcessDpiAwareness(PROCESS_PER_MONITOR_DPI_AWARE);
	DialogBox(hInstance, MAKEINTRESOURCE(IDD_DIALOG1), NULL, mainwindow);
	return 0;
}
