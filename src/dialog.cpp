// App功能实现文件

#include "stdafx.h"
#include "mfc_project.h"
#include "dialog.h"

#ifdef _DEBUG
#define new DEBUG_NEW
#endif


// 菜单项对话框
DWORD WINAPI lixsinff_CapThread(LPVOID lpParameter);

class MyInforDialog : public CDialog
{
public:
	MyInforDialog();
    
	enum { IDD = IDD_ABOUTBOX };
	protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

protected:
	DECLARE_MESSAGE_MAP()
};

MyInforDialog::MyInforDialog() : CDialog(MyInforDialog::IDD)
{

}

void MyInforDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
}

BEGIN_MESSAGE_MAP(MyInforDialog, CDialog)
END_MESSAGE_MAP()


// MyDialog 对话框

MyDialog::MyDialog(CWnd* pParent)
	: CDialog(MyDialog::IDD, pParent)
{

}

// 数据格式转换
void MyDialog::DoDataExchange(CDataExchange* pDX)
{
	CDialog::DoDataExchange(pDX);
	DDX_Control(pDX, IDC_BUTTON1, m_buttonStart);
	DDX_Control(pDX, IDC_BUTTON2, m_buttonStop);
	DDX_Control(pDX, IDC_COMBO1, m_comboBox);
	DDX_Control(pDX, IDC_COMBO2, m_comboBoxRule);
	DDX_Control(pDX, IDC_LIST1, m_listCtrl);
	DDX_Control(pDX, IDC_TREE1, m_treeCtrl);
	DDX_Control(pDX, IDC_EDIT1, m_edit);
}

BEGIN_MESSAGE_MAP(MyDialog, CDialog)
	ON_WM_SYSCOMMAND()
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()

	ON_BN_CLICKED(IDC_BUTTON1, &MyDialog::OnBnClickedButton1)
	ON_BN_CLICKED(IDC_BUTTON2, &MyDialog::OnBnClickedButton2)
	ON_NOTIFY(LVN_ITEMCHANGED, IDC_LIST1, &MyDialog::OnLvnItemchangedList1)
	ON_NOTIFY(NM_CUSTOMDRAW, IDC_LIST1, &MyDialog::OnNMCustomdrawList1)
END_MESSAGE_MAP()


// MyDialog 初始化
BOOL MyDialog::OnInitDialog()
{
	CDialog::OnInitDialog();

	ASSERT((IDM_ABOUTBOX & 0xFFF0) == IDM_ABOUTBOX);
	ASSERT(IDM_ABOUTBOX < 0xF000);

	CMenu* pSysMenu = GetSystemMenu(FALSE);
	if (pSysMenu != NULL)
	{
		CString strAboutMenu;
		strAboutMenu.LoadString(IDS_ABOUTBOX);
		if (!strAboutMenu.IsEmpty())
		{
			pSysMenu->AppendMenu(MF_SEPARATOR);
			pSysMenu->AppendMenu(MF_STRING, IDM_ABOUTBOX, strAboutMenu);
		}
	}

	ShowWindow(SW_MINIMIZE);

    m_listCtrl.SetExtendedStyle(LVS_EX_FULLROWSELECT|LVS_EX_GRIDLINES);

	m_listCtrl.InsertColumn(0,_T("Index"),3,50);
	m_listCtrl.InsertColumn(1, _T("Protocol Type"), 3, 120);
	m_listCtrl.InsertColumn(2,_T("Length"),3,72);
	m_listCtrl.InsertColumn(3, _T("Time"), 3, 90);
	m_listCtrl.InsertColumn(4,_T("Source MAC"),3,140);
	m_listCtrl.InsertColumn(5,_T("Destination MAC"),3,140);
	m_listCtrl.InsertColumn(6,_T("Source IP"),3,145);
	m_listCtrl.InsertColumn(7,_T("Destination IP"),3,145);

	m_comboBox.AddString(_T("Please choose an adapter"));
	m_comboBoxRule.AddString(_T("Please set filter rule"));
	
	if(MySniffer_initCap()<0)
		return FALSE;

	//初始化过滤规则
	m_comboBoxRule.AddString(_T("tcp"));
	m_comboBoxRule.AddString(_T("udp"));
	m_comboBoxRule.AddString(_T("ip"));
	m_comboBoxRule.AddString(_T("icmp"));
	m_comboBoxRule.AddString(_T("arp"));

	//初始化网卡列表
	for(dev=alldev;dev;dev=dev->next)
	{
		if(dev->description)
			m_comboBox.AddString(CString(dev->description));
	}   

	m_comboBox.SetCurSel(0);
	m_comboBoxRule.SetCurSel(0);
	m_buttonStop.EnableWindow(FALSE);

	return TRUE;
}

// 直接继承父类
void MyDialog::OnSysCommand(UINT nID, LPARAM lParam)
{
	if ((nID & 0xFFF0) == IDM_ABOUTBOX)
	{
		MyInforDialog dlgAbout;
		dlgAbout.DoModal();
	}
	else
	{
		CDialog::OnSysCommand(nID, lParam);
	}
}

// 绘制界面
void MyDialog::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this);

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
	}
	else
	{
		CDialog::OnPaint();
	}
}

HCURSOR MyDialog::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}

// 为组件绑定事件

// 开始捕获按钮点击事件
void MyDialog::OnBnClickedButton1()
{
	if(this->m_localDataList.IsEmpty() == FALSE)
	{
		if(MessageBox(_T("Please reconfirm that you do not need to save the data?"),_T("Warning"),MB_YESNO)==IDNO)
		{
			return;
		}
	}

	this->npkt =1;
	this->m_localDataList.RemoveAll();
	this->m_netDataList.RemoveAll();
	memset(&(this->npacket),0,sizeof(struct pktcount));

	if(this->MySniffer_startCap()<0)
		return;
	this->m_listCtrl.DeleteAllItems();
	this->m_treeCtrl.DeleteAllItems();
	this->m_edit.SetWindowTextW(_T(""));

	this->m_buttonStop.EnableWindow(TRUE);
	this->m_buttonStart.EnableWindow(FALSE);
}

// 结束按钮点击事件
void MyDialog::OnBnClickedButton2()
{
	if(NULL == this->m_ThreadHandle )
		return;
	if(TerminateThread(this->m_ThreadHandle,-1)==0)
	{
		MessageBox(_T("线程关闭发生错误"));
		return;
	}

	this->m_ThreadHandle = NULL;
	this->m_buttonStop.EnableWindow(FALSE);	
	this->m_buttonStart.EnableWindow(TRUE);
}

// 列表更新
void MyDialog::OnLvnItemchangedList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLISTVIEW pNMLV = reinterpret_cast<LPNMLISTVIEW>(pNMHDR);
	int index;
	index = this->m_listCtrl.GetHotItem();

	if(index>this->m_localDataList.GetCount()-1)
		return;

	this->MySniffer_updateEdit(index);
	this->MySniffer_updateTree(index);
	*pResult = 0;
}

//改变捕获包每行颜色
void MyDialog::OnNMCustomdrawList1(NMHDR *pNMHDR, LRESULT *pResult)
{
	LPNMLVCUSTOMDRAW pNMCD = (LPNMLVCUSTOMDRAW)pNMHDR;
	*pResult = 0;

	if(CDDS_PREPAINT==pNMCD->nmcd.dwDrawStage)
	{
		*pResult = CDRF_NOTIFYITEMDRAW;
	}else if(CDDS_ITEMPREPAINT ==pNMCD->nmcd.dwDrawStage){
		COLORREF crText;
		char buf[10];
		memset(buf,0,10);
		POSITION pos = this->m_localDataList.FindIndex(pNMCD->nmcd.dwItemSpec);
		struct datapkt * local_data = (struct datapkt *)this->m_localDataList.GetAt(pos);
		strcpy(buf,local_data->pktType);

		if(strcmp(buf,"IPV6")==0)
			crText = RGB(111,224,254);
		else if(strcmp(buf,"ARP")==0)
				crText = RGB(226,238,227);
		else if(strcmp(buf,"UDP")==0)
			crText = RGB(194,195,252);				
		else if(strcmp(buf,"TCP")==0)
				crText = RGB(230,230,230);
		else if(strcmp(buf,"ICMP")==0)
				crText = RGB(49,164,238);

		pNMCD->clrTextBk =crText;
		*pResult = CDRF_DODEFAULT;
	}
}

//初始化winpcap
int MyDialog::MySniffer_initCap()
{
	devCount = 0;
	if(pcap_findalldevs(&alldev, errbuf) ==-1)
		return -1;
	for(dev=alldev;dev;dev=dev->next)
		devCount++;	
	return 0;
}

//开始捕获
int MyDialog::MySniffer_startCap()
{	
	int if_index,filter_index,count;
	u_int netmask;
	struct bpf_program fcode;

	MySniffer_initCap();

	//获得接口和过滤器索引
	if_index = this->m_comboBox.GetCurSel();
	filter_index = this->m_comboBoxRule.GetCurSel();

	if(0==if_index || CB_ERR == if_index)
	{
		MessageBox(_T("请选择目标网卡"));
		return -1;
	}
	if(CB_ERR == filter_index)
	{
		MessageBox(_T("过滤规则非法"));	
		return -1;
	}

	/*获得选中的网卡接口*/
	dev=alldev;
	for(count=0;count<if_index-1;count++)
		dev=dev->next;
    
	if ((adhandle= pcap_open_live(dev->name,	// 设备名
							 65536,											//捕获数据包长度																					
							 1,													// 混杂模式 (非0意味着是混杂模式)
							 1000,												// 读超时设置
							 errbuf											// 错误信息
							 )) == NULL)
	{
		MessageBox(_T("无法打开此网卡："+CString(dev->description)));	
		pcap_freealldevs(alldev);
		return -1;
	}    

	//检查是否为以太网
	if(pcap_datalink(adhandle)!=DLT_EN10MB)
	{
		MessageBox(_T("非以太网"));
		pcap_freealldevs(alldev);
		return -1;
	}

	if(dev->addresses!=NULL)	
		netmask=((struct sockaddr_in *)(dev->addresses->netmask))->sin_addr.S_un.S_addr;
	else
		netmask=0xffffff; 

	//编译过滤器
	if(0==filter_index)
	{
		char filter[] = "";
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0 )
		{
			MessageBox(_T("语法错误"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}else{
		CString str;
		char *filter;
		int len,x;
		this->m_comboBoxRule.GetLBText(filter_index,str);
		len = str.GetLength()+1;
		filter = (char*)malloc(len);
		for(x=0;x<len;x++)
		{
			filter[x] = str.GetAt(x);
		}
		if (pcap_compile(adhandle, &fcode, filter, 1, netmask) <0 )
		{
			MessageBox(_T("语法错误"));
			pcap_freealldevs(alldev);
			return -1;
		}
	}


	//设置过滤器
	if (pcap_setfilter(adhandle, &fcode)<0)
	{
		MessageBox(_T("设置过滤规则错误"));
		pcap_freealldevs(alldev);
		return -1;
	}

	/* 设置数据包存储路径*/
	CFileFind file;
	char thistime[30];
	struct tm *ltime;
	memset(filepath,0,512);
	memset(filename,0,64);

	if(!file.FindFile(_T("SavedData")))
	{
		CreateDirectory(_T("SavedData"),NULL);
	}

	time_t nowtime;
	time(&nowtime);
	ltime=localtime(&nowtime);
	strftime(thistime,sizeof(thistime),"%Y%m%d %H%M%S",ltime);	
	strcpy(filepath,"SavedData\\");
	strcat(filename,thistime);
	strcat(filename,".lix");

	strcat(filepath,filename);
	dumpfile = pcap_dump_open(adhandle, filepath);
	if(dumpfile==NULL)
	{
		MessageBox(_T("文件创建失败"));
		return -1; 
	}

	pcap_freealldevs(alldev);	

	/*接收数据，新建线程处理*/
	LPDWORD threadCap=NULL;
	m_ThreadHandle=CreateThread(NULL,0,lixsinff_CapThread,this,0,threadCap);
	if(m_ThreadHandle==NULL)
	{
		int code=GetLastError();
		CString str;
		str.Format(_T("线程创建失败，代码为%d."),code);
		MessageBox(str);
		return -1;
	}
	return 1;
}

DWORD WINAPI lixsinff_CapThread(LPVOID lpParameter)
{
	int res,nItem ;
	struct tm *ltime;
	CString timestr,buf,srcMac,destMac;
	time_t local_tv_sec;
	struct pcap_pkthdr *header;									  //数据包头
	const u_char *pkt_data=NULL,*pData=NULL;     //网络中收到的字节流数据
	u_char *ppkt_data;
	
	MyDialog *pthis = (MyDialog*) lpParameter;
	if(NULL == pthis->m_ThreadHandle)
	{
		MessageBox(NULL,_T("线程句柄错误"),_T("提示"),MB_OK);
		return -1;
	}
	
	while((res = pcap_next_ex( pthis->adhandle, &header, &pkt_data)) >= 0)
	{
		if(res == 0)				//超时
			continue;
		
		struct datapkt *data = (struct datapkt*)malloc(sizeof(struct datapkt));		
		memset(data,0,sizeof(struct datapkt));

		if(NULL == data)
		{
			MessageBox(NULL,_T("储存空间已满，无法接收新的数据包"),_T("Error"),MB_OK);
			return -1;
		}

 	    //分析出错或所接收数据包不在处理范围内
		if(analyze_frame(pkt_data,data,&(pthis->npacket))<0)
			continue;  
		
		//将数据包保存到打开的文件中
		if(pthis->dumpfile!=NULL)
		{
			pcap_dump((unsigned char*)pthis->dumpfile,header,pkt_data);
		}

		//更新各类数据包计数
		pthis->MySniffer_updateNPacket();

		//将本地化后的数据装入一个链表中，以便后来使用		
		ppkt_data = (u_char*)malloc(header->len);
		memcpy(ppkt_data,pkt_data,header->len);

		pthis->m_localDataList.AddTail(data);
		pthis->m_netDataList.AddTail(ppkt_data);
	
		/*预处理，获得时间、长度*/
		data->len = header->len;								//链路中收到的数据长度
		local_tv_sec = header->ts.tv_sec;
		ltime = localtime(&local_tv_sec);
		data->time[0] = ltime->tm_year+1900;
		data->time[1] = ltime->tm_mon+1;
		data->time[2] = ltime->tm_mday;
		data->time[3] = ltime->tm_hour;
		data->time[4] = ltime->tm_min;
		data->time[5] = ltime->tm_sec;

		/*为新接收到的数据包在listControl中新建一个item*/
		buf.Format(_T("%d"),pthis->npkt);
		nItem = pthis->m_listCtrl.InsertItem(pthis->npkt,buf);

		/*显示时间戳*/
		timestr.Format(_T("%d/%d/%d  %d:%d:%d"),data->time[0],
			data->time[1],data->time[2],data->time[3],data->time[4],data->time[5]);
		pthis->m_listCtrl.SetItemText(nItem,1,timestr);
		//pthis->m_listCtrl.setitem
		
		/*显示长度*/
		buf.Empty();
		buf.Format(_T("%d"),data->len);
		pthis->m_listCtrl.SetItemText(nItem,2,buf);

		/*显示源MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->src[0],data->ethh->src[1],
							data->ethh->src[2],data->ethh->src[3],data->ethh->src[4],data->ethh->src[5]);
		pthis->m_listCtrl.SetItemText(nItem,3,buf);

		/*显示目的MAC*/
		buf.Empty();
		buf.Format(_T("%02X-%02X-%02X-%02X-%02X-%02X"),data->ethh->dest[0],data->ethh->dest[1],
							data->ethh->dest[2],data->ethh->dest[3],data->ethh->dest[4],data->ethh->dest[5]);
		pthis->m_listCtrl.SetItemText(nItem,4,buf);

		/*获得协议*/
		pthis->m_listCtrl.SetItemText(nItem,5,CString(data->pktType));

		/*获得源IP*/
		buf.Empty();
		if(0x0806== data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_srcip[0],
				data->arph->ar_srcip[1],data->arph->ar_srcip[2],data->arph->ar_srcip[3]);			
		}else if(0x0800 == data->ethh->type) {
			struct  in_addr in;
			in.S_un.S_addr = data->iph->saddr;
			buf = CString(inet_ntoa(in));
		}else if(0x86dd ==data->ethh->type ){
			int n;
			for(n=0;n<8;n++)
			{			
				if(n<=6)
					buf.AppendFormat(_T("%02x:"),data->iph6->saddr[n]);		
				else
					buf.AppendFormat(_T("%02x"),data->iph6->saddr[n]);		
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,6,buf);

		/*获得目的IP*/
		buf.Empty();
		if(0x0806 == data->ethh->type)
		{
			buf.Format(_T("%d.%d.%d.%d"),data->arph->ar_destip[0],
				data->arph->ar_destip[1],data->arph->ar_destip[2],data->arph->ar_destip[3]);			
		}else if(0x0800 == data->ethh->type){
			struct  in_addr in;
			in.S_un.S_addr = data->iph->daddr;
			buf = CString(inet_ntoa(in));
		}else if(0x86dd ==data->ethh->type ){
			int n;
			for(n=0;n<8;n++)
			{			
				if(n<=6)
					buf.AppendFormat(_T("%02x:"),data->iph6->daddr[n]);		
				else
					buf.AppendFormat(_T("%02x"),data->iph6->daddr[n]);		
			}
		}
		pthis->m_listCtrl.SetItemText(nItem,7,buf);
	
		/*对包计数*/
		pthis->npkt++;
	
	}
	return 1;
}

//更新信息
int MyDialog::MySniffer_updateEdit(int index)
{
	POSITION localpos,netpos;
	localpos = this->m_localDataList.FindIndex(index);
	netpos = this->m_netDataList.FindIndex(index);

	struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));
	u_char * net_data = (u_char*)(this->m_netDataList.GetAt(netpos));

	CString buf;
	print_packet_hex(net_data,local_data->len,&buf);
	//this-
	this->m_edit.SetWindowText(buf);

	return 1;
}

//更新树形控件
int MyDialog::MySniffer_updateTree(int index)
{
	POSITION localpos;
	CString str;
	int i;
	
	this->m_treeCtrl.DeleteAllItems();

	localpos = this->m_localDataList.FindIndex(index);
	struct datapkt* local_data = (struct datapkt*)(this->m_localDataList.GetAt(localpos));
	
	HTREEITEM root = this->m_treeCtrl.GetRootItem();
	str.Format(_T("Packet Index: %d"),index+1);
	HTREEITEM data = this->m_treeCtrl.InsertItem(str,root);

	/*处理帧数据*/
	HTREEITEM frame = this->m_treeCtrl.InsertItem(_T("Data Link Layer"),data);
	//源MAC
	str.Format(_T("Src MAC："));
	for(i=0;i<6;i++)
	{
		if(i<=4)
			str.AppendFormat(_T("%02x-"),local_data->ethh->src[i]);
		else
			str.AppendFormat(_T("%02x"),local_data->ethh->src[i]);
	}
	this->m_treeCtrl.InsertItem(str,frame);
	//目的MAC
	str.Format(_T("Dst MAC："));
	for(i=0;i<6;i++)
	{
		if(i<=4)
			str.AppendFormat(_T("%02x-"),local_data->ethh->dest[i]);
		else
			str.AppendFormat(_T("%02x"),local_data->ethh->dest[i]);
	}
	this->m_treeCtrl.InsertItem(str,frame);
	//类型
	str.Format(_T("Type：0x%02x"),local_data->ethh->type);
	this->m_treeCtrl.InsertItem(str,frame);

	/*处理IP、ARP*/
	if(0x0806 == local_data->ethh->type)							//ARP
	{
		HTREEITEM arp = this->m_treeCtrl.InsertItem(_T("ARP Header"),data);
		str.Format(_T("Hrd Type：%d"),local_data->arph->ar_hrd);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("Proto Type：0x%02x"),local_data->arph->ar_pro);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("HrdAddr Len：%d"),local_data->arph->ar_hln);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("ProtoAddr Len：%d"),local_data->arph->ar_pln);
		this->m_treeCtrl.InsertItem(str,arp);
		str.Format(_T("Operation：%d"),local_data->arph->ar_op);
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("Src MAC："));
		for(i=0;i<6;i++)
		{
			if(i<=4)
				str.AppendFormat(_T("%02x-"),local_data->arph->ar_srcmac[i]);
			else
				str.AppendFormat(_T("%02x"),local_data->arph->ar_srcmac[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("Src IP："),local_data->arph->ar_hln);
		for(i=0;i<4;i++)
		{
			if(i<=2)
				str.AppendFormat(_T("%d."),local_data->arph->ar_srcip[i]);
			else
				str.AppendFormat(_T("%d"),local_data->arph->ar_srcip[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("Dst MAC："),local_data->arph->ar_hln);
		for(i=0;i<6;i++)
		{
			if(i<=4)
				str.AppendFormat(_T("%02x-"),local_data->arph->ar_destmac[i]);
			else
				str.AppendFormat(_T("%02x"),local_data->arph->ar_destmac[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

		str.Format(_T("Dst IP："),local_data->arph->ar_hln);
		for(i=0;i<4;i++)
		{
			if(i<=2)
				str.AppendFormat(_T("%d."),local_data->arph->ar_destip[i]);
			else
				str.AppendFormat(_T("%d"),local_data->arph->ar_destip[i]);
		}
		this->m_treeCtrl.InsertItem(str,arp);

	}else if(0x0800 == local_data->ethh->type){					//IP
		
		HTREEITEM ip = this->m_treeCtrl.InsertItem(_T("IP Header"),data);

		str.Format(_T("Version：%d"),local_data->iph->version);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("Header Len：%d"),local_data->iph->ihl);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("Type：%d"),local_data->iph->tos);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("Total Len：%d"),local_data->iph->tlen);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("ID：0x%02x"),local_data->iph->id);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("Offset：%d"),local_data->iph->frag_off);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("TTL：%d"),local_data->iph->ttl);
		this->m_treeCtrl.InsertItem(str,ip);
		str.Format(_T("Proto：%d"),local_data->iph->proto);
		this->m_treeCtrl.InsertItem(str,ip);		
		str.Format(_T("Checksum：0x%02x"),local_data->iph->check);
		this->m_treeCtrl.InsertItem(str,ip);

		str.Format(_T("Src IP："));
		struct in_addr in;
		in.S_un.S_addr = local_data->iph->saddr;		
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str,ip);

		str.Format(_T("Dst IP："));
		in.S_un.S_addr = local_data->iph->daddr;		
		str.AppendFormat(CString(inet_ntoa(in)));
		this->m_treeCtrl.InsertItem(str,ip);

		/*处理传输层ICMP、UDP、TCP*/
		if(1 == local_data->iph->proto )							//ICMP
		{
			HTREEITEM icmp = this->m_treeCtrl.InsertItem(_T("ICMP Header"),data);
				
			str.Format(_T("Type: %d"),local_data->icmph->type);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("Code: %d"),local_data->icmph->code);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("Seq: %d"),local_data->icmph->seq);
			this->m_treeCtrl.InsertItem(str,icmp);
			str.Format(_T("Checksum: %d"),local_data->icmph->chksum);
			this->m_treeCtrl.InsertItem(str,icmp);

		}else if(6 == local_data->iph->proto){				//TCP
			
			HTREEITEM tcp = this->m_treeCtrl.InsertItem(_T("TCP Header"),data);

			str.Format(_T("Src Port: %d"),local_data->tcph->sport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("Dst Port: %d"),local_data->tcph->dport);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("Seq: 0x%02x"),local_data->tcph->seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("ACK Seq: %d"),local_data->tcph->ack_seq);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("Len: %d"),local_data->tcph->doff);

			HTREEITEM flag = this->m_treeCtrl.InsertItem(_T("Flag"),tcp);
	
			str.Format(_T("cwr %d"),local_data->tcph->cwr);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ece %d"),local_data->tcph->ece);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("urg %d"),local_data->tcph->urg);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("ack %d"),local_data->tcph->ack);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("psh %d"),local_data->tcph->psh);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("rst %d"),local_data->tcph->rst);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("syn %d"),local_data->tcph->syn);
			this->m_treeCtrl.InsertItem(str,flag);
			str.Format(_T("fin %d"),local_data->tcph->fin);
			this->m_treeCtrl.InsertItem(str,flag);

			str.Format(_T("Urg Ptr:%d"),local_data->tcph->urg_ptr); // 紧急指针
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("Checksum:0x%02x"),local_data->tcph->check);
			this->m_treeCtrl.InsertItem(str,tcp);
			str.Format(_T("Option:%d"),local_data->tcph->opt);
			this->m_treeCtrl.InsertItem(str,tcp);
		}else if(17 == local_data->iph->proto){				//UDP
			HTREEITEM udp = this->m_treeCtrl.InsertItem(_T("UDP Header"),data);
				
			str.Format(_T("Src Port: %d"),local_data->udph->sport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("Dst Port: %d"),local_data->udph->dport);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("Total Len: %d"),local_data->udph->len);
			this->m_treeCtrl.InsertItem(str,udp);
			str.Format(_T("Checksum: 0x%02x"),local_data->udph->check);
			this->m_treeCtrl.InsertItem(str,udp);
		}
	}

	return 1;
}
