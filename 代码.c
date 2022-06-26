/*这里我把四个函数的实现代码放在一起，便于老师查看*/

/*Note:仅是方便查看，不是用来运行的，函数的实现在内核中已有*/


/*getdents函数--------------------------------------------------------------*/

struct linux_dirent{
	long d_ino; 				//索引节点号（4字节）
	off_t d_off;				//在目录文件中的偏移（4字节）
	unsigned short d_reclen;	//文件名长（2字节）
	char d_name[14];			//文件名（14字节）
};
int sys_getdents(const unsigned int fd, struct linux_dirent *dirp,unsigned int count)
{
	int i,j,k;
	struct linux_dirent temp;
	int yyh=0;
	struct m_inode *inode = current->filp[fd]->f_inode;  //索引节点
	struct buffer_head *dir_head = bread(inode->i_dev,inode->i_zone[0]);  //dev设备号   block块号
	struct dir_entry *dir = (struct dir_entry *)dir_head->b_data;//第一个目录项
	
	for(i =0;i<1024;i++){
		if(dir->inode==0||(i+1)*24>count) break;  //不足24字节退出
		temp.d_ino = dir[i].inode;
		for(j=0;j<14;j++){
			temp.d_name[j] = dir[i].name[j];
		}
		temp.d_off=0;   
		temp.d_reclen=24;    //只占位不可以   	
		for(k=0;k<24;k++){
			//((char *)dirp)[yyh] = ((char*)&temp)[k];
			put_fs_byte(((char*)&temp)[k],((char*)dirp+yyh));	//这里必须使用 put_fs_byte()
			yyh++;
		}
	}
	return yyh;
}



/*getcwd函数-------------------------------------------------------------------*/
long sys_getcwd(char*buf,size_t size)
{
	int i,j,yyh,k;
	unsigned short the_last;
	struct m_inode *the_new_inode;
	char* temp[256]; //temp原因
	char ans[100]={0};
	struct m_inode *inode = current->pwd;   //当前目录的索引节点
	struct buffer_head *dir_head = bread(current->root->i_dev,inode->i_zone[0]);  //dev设备号   block块号
	struct dir_entry *dir = (struct dir_entry *)dir_head->b_data;//第一个目录项
	i = 0;
	if(dir==NULL) return -1;
	if(buf==NULL){
		buf = (char*)malloc(sizeof(char)*size);
	}
	while(1){
		the_last = dir->inode;
		the_new_inode = iget(current->root->i_dev,(dir+1)->inode);
		dir_head = bread(current->root->i_dev,the_new_inode->i_zone[0]);
		dir = (struct dir_entry*) dir_head->b_data;
		j = 1;
		while(1){
			if((dir+j)->inode==the_last) break;
			j++;
		}
		if(j==1) break;
		temp[i] = (dir+j)->name;
		i++;
	}
	yyh = 0;i--;
	while(i>=0){
		k = 0;
		ans[yyh++] = '/';
		while(temp[i][k]!='\0'){
			ans[yyh] = temp[i][k];
			k++;yyh++;
		}
		i--;
	}
	for(k=0;k<yyh;k++)	put_fs_byte(ans[k],buf+k);
	return (long)(ans);
}


/*sleep函数----------------------------------------------------------------*/
unsigned int sys_sleep(unsigned int seconds)
{
	if(sys_signal(14,SIG_IGN,NULL)==-1){ 	//忽略SIGALRM信号
		return -1;
	}
	sys_alarm(seconds); 			//seconds秒后进程收到SIGALRM信号
	sys_pause();					//睡眠
	return 0;
}


/*execve2函数--------------------------------------------------------------*/
void solve(){
	unsigned long temp;
	for(temp = current->start_code;temp<=current->start_code+current->end_data;temp+=4096){
		do_no_page_yyh(temp);
	}
}

int do_execve2(unsigned long * eip,long tmp,char * filename,
	char ** argv, char ** envp)
{
	struct m_inode * inode;
	struct buffer_head * bh;
	struct exec ex;
	unsigned long page[MAX_ARG_PAGES];
	int i,argc,envc;
	int e_uid, e_gid;
	int retval;
	int sh_bang = 0;
	unsigned long p=PAGE_SIZE*MAX_ARG_PAGES-4;

	if ((0xffff & eip[1]) != 0x000f)
		panic("execve2 called from supervisor mode");
	for (i=0 ; i<MAX_ARG_PAGES ; i++)	/* clear page-table */
		page[i]=0;
	if (!(inode=namei(filename)))		/* get executables inode */
		return -ENOENT;
	argc = count(argv);
	envc = count(envp);
	
restart_interp:
	if (!S_ISREG(inode->i_mode)) {	/* must be regular file */
		retval = -EACCES;
		goto exec_error2;
	}
	i = inode->i_mode;
	e_uid = (i & S_ISUID) ? inode->i_uid : current->euid;
	e_gid = (i & S_ISGID) ? inode->i_gid : current->egid;
	if (current->euid == inode->i_uid)
		i >>= 6;
	else if (current->egid == inode->i_gid)
		i >>= 3;
	if (!(i & 1) &&
	    !((inode->i_mode & 0111) && suser())) {
		retval = -ENOEXEC;
		goto exec_error2;
	}
	//page_fault();

	if (!(bh = bread(inode->i_dev,inode->i_zone[0]))) {
		retval = -EACCES;
		goto exec_error2;
	}
	ex = *((struct exec *) bh->b_data);	/* read exec-header */
	if ((bh->b_data[0] == '#') && (bh->b_data[1] == '!') && (!sh_bang)) {
		/*
		 * This section does the #! interpretation.
		 * Sorta complicated, but hopefully it will work.  -TYT
		 */

		char buf[1023], *cp, *interp, *i_name, *i_arg;
		unsigned long old_fs;

		strncpy(buf, bh->b_data+2, 1022);
		brelse(bh);
		iput(inode);
		buf[1022] = '\0';
		if (cp = strchr(buf, '\n')) {
			*cp = '\0';
			for (cp = buf; (*cp == ' ') || (*cp == '\t'); cp++);
		}
		if (!cp || *cp == '\0') {
			retval = -ENOEXEC; /* No interpreter name found */
			goto exec_error1;
		}
		interp = i_name = cp;
		i_arg = 0;
		for ( ; *cp && (*cp != ' ') && (*cp != '\t'); cp++) {
 			if (*cp == '/')
				i_name = cp+1;
		}
		if (*cp) {
			*cp++ = '\0';
			i_arg = cp;
		}
		/*
		 * OK, we've parsed out the interpreter name and
		 * (optional) argument.
		 */
		if (sh_bang++ == 0) {
			p = copy_strings(envc, envp, page, p, 0);
			p = copy_strings(--argc, argv+1, page, p, 0);
		}
		/*
		 * Splice in (1) the interpreter's name for argv[0]
		 *           (2) (optional) argument to interpreter
		 *           (3) filename of shell script
		 *
		 * This is done in reverse order, because of how the
		 * user environment and arguments are stored.
		 */
		p = copy_strings(1, &filename, page, p, 1);
		argc++;
		if (i_arg) {
			p = copy_strings(1, &i_arg, page, p, 2);
			argc++;
		}
		p = copy_strings(1, &i_name, page, p, 2);
		argc++;
		if (!p) {
			retval = -ENOMEM;
			goto exec_error1;
		}
		/*
		 * OK, now restart the process with the interpreter's inode.
		 */
		old_fs = get_fs();
		set_fs(get_ds());
		if (!(inode=namei(interp))) { /* get executables inode */
			set_fs(old_fs);
			retval = -ENOENT;
			goto exec_error1;
		}
		set_fs(old_fs);
		goto restart_interp;
	}
	brelse(bh);
	if (N_MAGIC(ex) != ZMAGIC || ex.a_trsize || ex.a_drsize ||
		ex.a_text+ex.a_data+ex.a_bss>0x3000000 ||
		inode->i_size < ex.a_text+ex.a_data+ex.a_syms+N_TXTOFF(ex)) {
		retval = -ENOEXEC;
		goto exec_error2;
	}
	if (N_TXTOFF(ex) != BLOCK_SIZE) {
		printk("%s: N_TXTOFF != BLOCK_SIZE. See a.out.h.", filename);
		retval = -ENOEXEC;
		goto exec_error2;
	}
	if (!sh_bang) {
		p = copy_strings(envc,envp,page,p,0);
		p = copy_strings(argc,argv,page,p,0);
		if (!p) {
			retval = -ENOMEM;
			goto exec_error2;
		}
	}
/* OK, This is the point of no return */
	if (current->executable)
		iput(current->executable);
	current->executable = inode;
	for (i=0 ; i<32 ; i++)
		current->sigaction[i].sa_handler = NULL;
	for (i=0 ; i<NR_OPEN ; i++)
		if ((current->close_on_exec>>i)&1)
			sys_close(i);
	current->close_on_exec = 0;
	free_page_tables(get_base(current->ldt[1]),get_limit(0x0f));
	free_page_tables(get_base(current->ldt[2]),get_limit(0x17));
	if (last_task_used_math == current)
		last_task_used_math = NULL;
	current->used_math = 0;
	p += change_ldt(ex.a_text,page)-MAX_ARG_PAGES*PAGE_SIZE;
	p = (unsigned long) create_tables((char *)p,argc,envc);
	current->brk = ex.a_bss +
		(current->end_data = ex.a_data +
		(current->end_code = ex.a_text));
	current->start_stack = p & 0xfffff000;
	current->euid = e_uid;
	current->egid = e_gid;


	i = ex.a_text+ex.a_data;
	while (i&0xfff)
		put_fs_byte(0,(char *) (i++));
	eip[0] = ex.a_entry;		/* eip, magic happens :-) */
	eip[3] = p;			/* stack pointer */

	solve();

	return 0;
exec_error2:
	iput(inode);
exec_error1:
	for (i=0 ; i<MAX_ARG_PAGES ; i++)
		free_page(page[i]);
	return(retval);
}