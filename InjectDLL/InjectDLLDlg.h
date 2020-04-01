
// InjectDLLDlg.h : header file
//

#pragma once


// CInjectDLLDlg dialog
class CInjectDLLDlg : public CDialogEx
{
// Construction
public:
	CInjectDLLDlg(CWnd* pParent = nullptr);	// standard constructor

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_INJECTDLL_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support


// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	CEdit m_ctrlDLLPath;
	CEdit m_ctrlPID;
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedButtonEject();
};
