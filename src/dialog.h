#pragma once
#include "afxcmn.h"
#include "afxwin.h"
#include "pcap.h"
#include "protocol_struct.h"
#include "utilities.h"

// MyDialog 类
class MyDialog : public CDialog
{
public:
	MyDialog(CWnd* pParent = NULL);
	
	int devCount;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_if_t *alldev;
	pcap_if_t *dev;
	pcap_t *adhandle;
	pcap_dumper_t *dumpfile;							

	int MySniffer_initCap();
	int MySniffer_startCap();
	int MySniffer_updateTree(int index);
	int MySniffer_updateEdit(int index);

	HANDLE m_ThreadHandle;			//线程
	CPtrList m_pktList;				//捕获包链表

	// 数据转换
	enum { IDD = IDD_MCF6_DIALOG };
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);

protected:
	HICON m_hIcon;

	virtual BOOL OnInitDialog();

	DECLARE_MESSAGE_MAP()
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();

public:
	int npkt;
	CEdit m_edit;
	CListCtrl m_listCtrl;
	CComboBox m_comboBox;
	CComboBox m_comboBoxRule;
	CTreeCtrl m_treeCtrl;
	CButton m_buttonStart;
	CButton m_buttonStop;

	afx_msg void OnBnClickedButton1();
	afx_msg void OnBnClickedButton2();
	afx_msg void OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult);
	afx_msg void OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult);
};
