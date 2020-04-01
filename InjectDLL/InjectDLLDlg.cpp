
// InjectDLLDlg.cpp : implementation file
//

#include "pch.h"
#include "framework.h"
#include "InjectDLL.h"
#include "InjectDLLDlg.h"
#include "afxdialogex.h"
#include "injectUtil.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// CAboutDlg dialog used for App About

class CAboutDlg : public CDialogEx
{
public:
	CAboutDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_ABOUTBOX };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

// Implementation
protected:
	DECLARE_MESSAGE_MAP()
};

CAboutDlg::CAboutDlg() : CDialogEx(IDD_ABOUTBOX)
{
}

void CAboutDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(CAboutDlg, CDialogEx)
END_MESSAGE_MAP()


// CInjectDLLDlg dialog



CInjectDLLDlg::CInjectDLLDlg(CWnd* pParent /*=nullptr*/)
	: CDialogEx(IDD_INJECTDLL_DIALOG, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}

void CInjectDLLDlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_EDIT_DLLPATH, m_ctrlDLLPath);
	DDX_Control(pDX, IDC_EDIT_PID, m_ctrlPID);
}

BEGIN_MESSAGE_MAP(CInjectDLLDlg, CDialogEx)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDOK, &CInjectDLLDlg::OnBnClickedOk)
	ON_BN_CLICKED(IDC_BUTTON_EJECT, &CInjectDLLDlg::OnBnClickedButtonEject)
END_MESSAGE_MAP()


// CInjectDLLDlg message handlers

BOOL CInjectDLLDlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// Add "About..." menu item to system menu.

	// IDM_ABOUTBOX must be in the system command range.
	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != nullptr)
	{
		BOOL bNameValid;
		CString strAboutMenu;
		bNameValid = strAboutMenu.LoadString(IDS_ABOUTBOX);
		ASSERT(bNameValid);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	// Set the icon for this dialog.  The framework does this automatically
	//  when the application's main window is not a dialog
	SetIcon(m_hIcon, TRUE);			// Set big icon
	SetIcon(m_hIcon, FALSE);		// Set small icon

	// TODO: Add extra initialization here
	if (!SetDebugPrivilege())
	{
		AfxMessageBox(_T("FailSetDebugPrivilege "));
		return FALSE;
	}
	CString strDLLPath;
	WCHAR szCurPath[MAX_PATH] = { 0, };

	GetModuleFileName(NULL, szCurPath, MAX_PATH);
	PathRemoveFileSpec(szCurPath);
#ifndef _WIN64
	SetWindowText(_T("InjectDLL x86"));
	strDLLPath.Format(_T("%s\\dummy32.dll"), szCurPath);
#else
	SetWindowText(_T("InjectDLL x64"));
	strDLLPath.Format(_T("%s\\dummy64.dll"), szCurPath);
#endif
	m_ctrlDLLPath.SetWindowTextW(strDLLPath);
	return TRUE;  // return TRUE  unless you set the focus to a control
}

void CInjectDLLDlg::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		CAboutDlg dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialogEx::OnSysCommand(nID, lParam);
	}
}

// If you add a minimize button to your dialog, you will need the code below
//  to draw the icon.  For MFC applications using the document/view model,
//  this is automatically done for you by the framework.

void CInjectDLLDlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // device context for painting

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// Center icon in client rectangle
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// Draw the icon
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}

// The system calls this function to obtain the cursor to display while the user drags
//  the minimized window.
HCURSOR CInjectDLLDlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}



void CInjectDLLDlg::OnBnClickedOk()
{
	// TODO: Add your control notification handler code here
	CString strPID;
	CString strDLLPath;
	DWORD dwPID = -1;

	if (m_ctrlDLLPath.GetWindowTextLength() == 0 ||
		m_ctrlPID.GetWindowTextLength() == 0)
	{
		AfxMessageBox(_T("invalid input"));
		return;
	}

	m_ctrlDLLPath.GetWindowText(strDLLPath);
	m_ctrlPID.GetWindowText(strPID);
	dwPID = _ttoi(strPID);
	
	if (!DLLInjectByRemoteThread(dwPID, strDLLPath.GetBuffer()))
	{
		AfxMessageBox(_T("fail  DLLInjectByRemoteThread"));
	}
	else
	{
		AfxMessageBox(_T("success  DLLInjectByRemoteThread"));
	}


}


void CInjectDLLDlg::OnBnClickedButtonEject()
{
	CString strPID;
	CString strDLLPath;
	DWORD dwPID = -1;

	if (m_ctrlDLLPath.GetWindowTextLength() == 0 ||
		m_ctrlPID.GetWindowTextLength() == 0)
	{
		AfxMessageBox(_T("invalid input"));
		return;
	}

	m_ctrlDLLPath.GetWindowText(strDLLPath);
	m_ctrlPID.GetWindowText(strPID);
	dwPID = _ttoi(strPID);

	if (!DLLEjectByRemoteThread(dwPID, strDLLPath.GetBuffer()))
	{
		AfxMessageBox(_T("fail  DLLEjectByRemoteThread"));
	}
	else
	{
		AfxMessageBox(_T("success  DLLEjectByRemoteThread"));
	}
}
