#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include "re2dfa.h"

//tokenise=============================================================================================================
struct tokenNode
{
	char symbol1;
	char op;
	char symbol2;
	void *littleArray1;//call tokenArray typecast
	void *littleArray2;//call tokenArray typecast

	//store NULL or 0 if nothing is present
};

struct tokenArray
{
	struct tokenNode *list;
	int tokenCount;
};

// Mathematical tools +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

int *binMapUnion(int *a, int *b, int symbolCount)
{
	int *t = (int *)malloc((symbolCount+1) * sizeof(int));
	int i;
	
	for( i = 1; i <= symbolCount; i++ ) t[i] = a[i] | b[i];

	return t;
}

int *toBinaryMap(int *a, int n, int symbolCount)
{
	int i;
	symbolCount = symbolCount + 1;
	int *b = (int *)malloc(symbolCount * sizeof(int));

	for( i = 0; i < n; i++ ) b[a[i]] = 1;
	return b; 
}

long long int toDecimal(int *a, int symbolCount)
{
	int i;
	long long int prev_exponent = 1, decimal = 0;
	for( i = symbolCount; i >= 1; i-- ){
		decimal += ( prev_exponent * a[i] );
		prev_exponent *= 2; 
	}
	return decimal;
}

int *Union(int a1[],int a2[],int n,int n1,int n2)
{
	int i,k=0;
	int *a = (int *)malloc((n)*sizeof(int));
	memset((void *)a, 0, (n));
	for(i=0;i<n1;i++)
	{
		k=a1[i];
		a[k-1]=1;

	}
	for(i=0;i<n2;i++)
	{
		k=a2[i];
		a[k-1]=1;
	}
	return a;
}

// insert a charachter at particular position in a string
void charins(char *S,char c,int n)
{
	int len = strlen(S);
	int i;
	for(i = len;i>n;i--)
	{
		S[i]=S[i-1];
	}
	S[n]=c;
	S[len+1]='\0';
}
// Mathematical tools ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

// function to normalize the given input RE and verify it
int normalizeRE(char *re)
{
	//this will cleanup re and remove stray spaces and extra characters
	//and any error in re return 1;
	int i,j,len,l, top;
	char brackets[REMAX];
	/*proper bracketting of the regular expression for the following cases :
		case 1 : a* | b* ==> (a*)|(b*)
		case 2 * (abb)*|(abc)* ===> ((abb)*)|((abc)*)	*/

	l = strlen(re);
	i=0;
	while(re[i]!='\0')
	{

		// case : a*|....
		if(isalpha(re[i])&&(re[i+1]=='*')&&(re[i+2] == '|'))
			{
				charins(re,'(',i);
				charins(re,')',i+3);
				i = i+4;
			}
		// case : ... | b*
		if(re[i]=='|' && (isalpha(re[i+1])) && (re[i+2] =='*'))
			{
				charins(re,'(',i+1);
				charins(re,')',i+4);
				i=i+4;
			}
		// case : ... ()*|b
		if(re[i]==')' && re[i+1]=='*' && re[i+2] == '|')
			{
				charins(re,')',i+2);
				int j=i;
				int top = 0;
				while(top !=-1)
				{
					j--;
					if(re[j]==')')
						top++;
					if(re[j] == '(')
						top--;
				}
				charins(re,'(',j);
				i=i+4;
			}
		//case : ....a|()*
		if(re[i]=='|' && re[i+1]=='(' )
		{
			int z = i;
			int k =i;
			k++;
			int top=0;
			while(top != -1)
			{
				k++;
				if(re[k]=='(')
					top++;
				if(re[k]==')')
					top--;
			}
			if(re[k+1]=='*')
				{
					charins(re,')',k+2);
					charins(re,'(',z+1);
					i=k+2;
				}

		}

		i++;
	}


	len =strlen(re);

	//enter # to mark end
	//augmented RE
	re[len]='#';
	re[len+1]='\0';
	len=len+1;



	//space cleanup and stray operator
	for(i=0;i<len;i++)
	{
		if(re[i]==' ')
		{
			for(j=i;j<len;j++)
				re[j] = re[j+1];
			i--;
			len--;
		}

		if(!(re[i]=='*'||re[i]=='|'||re[i]==' '||re[i]=='+'||re[i]=='('||re[i]==')'||isalpha(re[i])||re[i]=='#'))
		{
			printf("Stray operator/symbol '%c' at %d!\n",re[i],i+1);
			return 1;
		}
	}

	//unwanted repeated operator detection
	for(i=0;i<len-1;i++)
	{
		if(((re[i]=='*'||re[i]=='|'||re[i]=='+'||re[i]=='#')&&(re[i] == re[i+1]))||(re[i]=='*'&&re[i+1]=='+')||(re[i]=='+'&&re[i+1]=='*'))
		{
			printf("Wrongly repeated operator '%c' at %d!\n",re[i],i+1);
			return 1;
		}
	}

	//check paranthesis
	top=0;
	for(i=0;i<len;i++)
	{
		if(re[i]=='(')
		{
			brackets[top++]='(';
		}
		else if(re[i]==')')
		{
			if((top>0)&&(brackets[top-1]=='('))
				top--;
			else
			{
				printf("Parenthesis not matching at %d!\n",i+1);
				return 1;
			}
		}
	}

	if(top!=0)
	{
		printf("Parenthesis not matching!\n");
		return 1;
	}
	return 0;
}

int countSymbols(char *re, int *uniqCount, char *uni_str)
{
	int n=strlen(re),i,c=0;
	int uniqMarkArr[300]={0};
	*uniqCount=0;
	for(i=0;i<n;i++)
	{
		if(isalpha(re[i])||re[i]=='#')
		{
			c++;
			if(uniqMarkArr[re[i]]==0 && re[i]!='e')
			{
				uni_str[(*uniqCount)] = re[i];
				(*uniqCount)++;
				uniqMarkArr[re[i]] = 1;
			}
		}
	}
	return c;
}

struct tokenArray *initTokenArray(char *re)
{
	//this function will initialize and build list array according to RE size
	// storing the length of the regular expression
  struct tokenArray *arr;
	arr=(struct tokenArray*)malloc(sizeof(struct tokenArray));

	int len = strlen(re);
	int i,top =-1;
	// variable to store no.of tokens
	int Count =0;
	// counting the no.of tokens in the regular expression
	for(i=0;i<(len);i++)
	{
		// Taking an expression enclosed in () or ()* or ()|() or ()|a paranthesis as a single token
		if(re[i] == '(')
		{
			Count++;
			top++;
			// Taking the first expression within ()
			while(top!=-1)
			{
				i++;
				if(re[i]=='(')
					top++;
				if(re[i]==')')
					top--;
			}
			// Taking  a single token as ()*
			if(re[i+1]=='*')
				i++;
			// taking a single Token as ()|() or ()|a
			else if(re[i+1] == '|')
			{
				i++;
				if(isalpha(re[i+1]))
					i++;
				else if(re[i+1]=='(')
				{
					i=i+1;
					top++;
					while(top!=-1)
					{
						i++;
						if(re[i]=='(')
							top++;
						if(re[i]==')')
							top--;
					}
				}
			}
		}
		// Taking a symbol with unary operator  t*
		else if(isalpha(re[i]) && re[i+1]=='*')
		{
			Count++;
			i++;
		}
		// Taking two symbols with binary operator "|" as a single token (i.e. a|b)
		else if(isalpha(re[i])&&re[i+1]=='|' && isalpha(re[i+2]))
		{
			Count++;
			i=i+2;
		}
		// Taking a single token as a|()
		else if(isalpha(re[i])&&re[i+1]=='|' && re[i+2] == '(')
		{
			Count++;
			i=i+2;
			top++;
			// Taking the first expression within ()
			while(top!=-1)
			{
				i++;
				if(re[i]=='(')
					top++;
				if(re[i]==')')
					top--;
			}
		}
		// Taking each symbol as individual token
		else
		{
				Count++;
		}
	}
		// Allocating the No.of Tokens
		arr->tokenCount = Count;
		// Allocating a memory for tokens
		arr->list =(struct tokenNode*)malloc((Count) * sizeof(struct tokenNode));
		return arr;
}

struct tokenArray *parseAndStoreTokens(char *re)
{
	//this function will parse tokens and store them in tokenArray

	// Initialize the tokenArray;
	struct tokenArray *arr;
	arr = initTokenArray(re);
	int len=strlen(re);
	int i,top=-1;
	int Count = 0;
	//Parse a single token as a content with in () or ()* or ()|() or ()|a

	for(i=0;i<(len);i++)
	{
		// Parse a single token whose 1st Little Array is ()
		if(re[i] == '(')
		{
			arr->list[Count].symbol1 = '\0';
			char buffer[REMAX];
			char buffer2[REMAX];
			int ind =-1;
			int ind2 =-1;
			top++;
			// parsing the contents within the paranthesis
			while(top!=-1)
			{
				i++;
				buffer[++ind]=re[i];
				if(re[i]=='(')
					top++;
				if(re[i]==')')
					top--;
			}
			top=-1;
			buffer[ind]='\0';
			// Recursuive call
			arr->list[Count].littleArray1 = parseAndStoreTokens(buffer);
			// Reset Buffer
			bzero((void *)buffer,ind);
			ind = -1;
			// Enter the Unary operator *
			if(re[i+1]=='*')
			{
				i++;
				arr->list[Count].op = re[i];
			}
			// For the Binary operator *
			else if(re[i+1] == '|')
			{
				i++;
				// Setting the operator
				arr->list[Count].op = re[i];
				if(re[i+1]=='(')
				{
					i++;
					top++;
					// Parsing the token for 2nd LittleArray
					while(top!=-1)
					{
						i++;
						buffer2[++ind2]=re[i];
						if(re[i]=='(')
							top++;
						if(re[i]==')')
							top--;
					}
					buffer2[ind2]='\0';
					// Reccursive call
					arr->list[Count].littleArray2 = parseAndStoreTokens(buffer2);
					arr->list[Count].symbol2 = '\0';
					//reset the buffer
					bzero((void *)buffer2,ind2);
					ind2 =-1;
				}
				// parsing the token as ()|a
				else
				{
					i++;
					arr->list[Count].symbol2=re[i];
					arr->list[Count].littleArray2 = NULL;
				}
					// Increase the token Node Count
			}
			else
			{
				arr->list[Count].littleArray2 = NULL;
				arr->list[Count].symbol2 = '\0';
				arr->list[Count].op = '\0';
			}
			// Increase the token Node Count
			Count++;
		}

		//Parse a single token as a content with a|() or a* or a|b or a
		else if (isalpha(re[i]))
		{
			char buffer[REMAX];
			int ind =-1;
			arr->list[Count].littleArray1 = NULL;
			arr->list[Count].symbol1 = re[i];
			// taking token as Single a
			if(isalpha(re[i+1])||re[i+1]=='#')
			{
				arr->list[Count].littleArray2 = NULL;
				arr->list[Count].symbol2 = '\0';
				arr->list[Count].op = '\0';
			}
			// setting the unary operator *
			else if (re[i+1] == '*')
			{
				i++;
				arr->list[Count].op = re[i];
				arr->list[Count].littleArray2 = NULL;
				arr->list[Count].symbol2 = '\0';
			}
			// setting the binary operator ' | '
			else if (re[i+1]=='|')
			{
				i++;
				arr->list[Count].op = re[i];
				// taking a single token as a|b
				if(isalpha(re[i+1]))
				{
					i++;
					arr->list[Count].littleArray2 = NULL;
					arr->list[Count].symbol2 = re[i];
				}
				// taking a single token as a|()
				else if(re[i+1]=='(')
				{
					i++;
					top++;
					// Parsing the token for 2nd LittleArray
					while(top!=-1)
					{
						i++;
						buffer[++ind]=re[i];
						if(re[i]=='(')
							top++;
						if(re[i]==')')
							top--;
					}
					buffer[ind]='\0';
					// Reccursive call
					arr->list[Count].littleArray2 = parseAndStoreTokens(buffer);
					arr->list[Count].symbol2 = '\0';
					//reset the buffer
					bzero((void *)buffer,ind);
					ind =-1;
				}
			}
			//Increase the Token Node Count
			Count++;
		}
		else if(re[i]=='#')
		{
			arr->list[Count].symbol1 = re[i];
			arr->list[Count].littleArray1 = NULL;
			arr->list[Count].op = '\0';
			arr->list[Count].littleArray2 = NULL;
			arr->list[Count].symbol2 = '\0';
		}
	}
	return arr;
}

void printTokenArray(struct tokenArray *arr)
{
	if(arr==NULL||arr->tokenCount==0||arr->list==NULL)
		return;

	int i;
	printf("\n");
	printf("\n No.of.Tokens :\t%d\n\n ",arr->tokenCount);
	for(i=0;i<arr->tokenCount;i++)
	{
		printf("\n");
		printf("Symbol 1: %c\n",arr->list[i].symbol1);
		printf("Operator: %c\n",arr->list[i].op);
		printf("Symbol 2: %c\n",arr->list[i].symbol2);
		if(arr->list[i].littleArray1!=NULL)
		{
			printf("little arr1 present\n");
			printf("\n  ****************************\n");
			printTokenArray(arr->list[i].littleArray1);
			printf("\n  ****************************\n");
		}
		if(arr->list[i].littleArray2!=NULL)
		{
			printf("little arr2 present\n");
			printf("\n ****************************\n");
			printTokenArray(arr->list[i].littleArray2);
			printf("\n ****************************\n");
		}
	printf("\n-------------------------------------\n");
	}
}

//tokenise=============================================================================================================




//syntax tree===========================================================================================================
struct posarray
{
	int poscount;
	int *poslist;

	//this data structure will store firstpos and lastpos
};

struct syntaxNode
{
	char data;
	int nullable;
	struct posarray firstpos;
	struct posarray lastpos;
	struct syntaxNode *leftchild;
	struct syntaxNode *rightchild;

	//for building syntax tree
};


struct syntaxNode *createSyntaxNode(char ch, int s_curr, int s_count)
{
	//build the node and return the node's address

	struct syntaxNode *newNode;
	newNode = (struct syntaxNode *)malloc(sizeof(struct syntaxNode));

	newNode->data = ch;
	newNode->nullable = 0;
	newNode->leftchild = NULL;
	newNode->rightchild = NULL;

	newNode->firstpos.poscount=0;
	newNode->firstpos.poslist = (int*)malloc(s_count*sizeof(int));

	newNode->lastpos.poscount=0;
	newNode->lastpos.poslist = (int*)malloc(s_count*sizeof(int));

	//support for epsilon
	if(ch=='e')
	{
		return newNode;
	}
	//if s_curr!=0, store pos s
	if(s_curr!=0)
	{
		newNode->firstpos.poslist[0] = s_curr;
		newNode->firstpos.poscount=1;

		newNode->lastpos.poslist[0] = s_curr;
		newNode->lastpos.poscount=1;
	}
	return newNode;

}

struct syntaxNode *Token2syntaxNode(struct tokenNode *token_n, int *flag, int *s_curr, int s_count)
{

	//flag: return 0 if no littlearray, 1 if littlearray 1, 2 if both, 3 if only littleArray2

	//take a new empty pointer
	struct syntaxNode *newNodePtr=NULL, *temp;
	*flag = 0;
	//cases:

	if(token_n->op=='*')
	{
		// * is present, build a node with star and store in new
		newNodePtr = createSyntaxNode('*', 0, s_count);
	}
	else if(token_n->op=='|')
	{
		// | is present,  build a node with pipe and store it in new
		newNodePtr = createSyntaxNode('|', 0, s_count);
	}


	// symbol1 present, increment s_curr, build a node and put char, tell to store pos s, if new is empty store there, else in new->leftchild
	if(token_n->symbol1!='\0')
	{
		(*s_curr)++;
		temp = createSyntaxNode(token_n->symbol1, *s_curr, s_count);
		if(newNodePtr==NULL)
			newNodePtr = temp;
		else
			newNodePtr->leftchild = temp;
	}

	// symbol2 present, increment s_curr, build a node and put char, tell to store pos s, and store in new->rightchild
	if(token_n->symbol2!='\0')
	{
		(*s_curr)++;
		temp = createSyntaxNode(token_n->symbol2, *s_curr, s_count);
		newNodePtr->rightchild = temp;
	}

	if(token_n->littleArray1==NULL && token_n->littleArray2==NULL)//littlearrays not present, flag=0
		*flag = 0;
	else if(token_n->littleArray1!=NULL && token_n->littleArray2==NULL)//littleArray1 present only, flag=1
		*flag = 1;
	else if(token_n->littleArray1!=NULL && token_n->littleArray2!=NULL)//littleArray1 present && littleArray2 present, flag=2
		*flag = 2;
	else if(token_n->littleArray1==NULL && token_n->littleArray2!=NULL)//littleArray2 present only, flag=3
		*flag = 3;

	//return new
	return newNodePtr;
}

struct syntaxNode *syntaxTreeBuilder(struct tokenArray *tokenarr, int *s_curr, int s_count)
{
	struct syntaxNode *synRoot=NULL, *synNew, *temp;
	int i, flag;

	//special handling for first token
	//take a node, store it in root
	synRoot = Token2syntaxNode(&(tokenarr->list[0]),&flag,s_curr,s_count);

	//if flag=1||2, call recursive littlearray1 and store it
	if(flag==1||flag==2)
	{
		temp = syntaxTreeBuilder((tokenarr->list[0]).littleArray1, s_curr,s_count);
		//if root is still NULL, store it there only,
		if(synRoot == NULL)
		{
			synRoot = temp;
		}
		else
		{
			//otherwise store it in root->leftchild
			synRoot->leftchild = temp;
		}
	}

	if(flag==2||flag==3)
	{
		//if flag=2||3, call recursive littleArray2 and store it in root->rightchild
		temp = syntaxTreeBuilder((tokenarr->list[0]).littleArray2, s_curr,s_count);
		synRoot->rightchild = temp;
	}


	//mini tree building loop
	for(i = 1; i < (tokenarr->tokenCount); i++)
	{
		//create a cat node and store it in new ptr
		synNew = createSyntaxNode('.', 0, s_count);

		//leftchild
		//store root in new->leftchild
		synNew->leftchild = synRoot;
		//store new in root, new root is created
		synRoot = synNew;

		//rightchild
		//take a node, store it in root->rightchild
		synRoot->rightchild = Token2syntaxNode(&(tokenarr->list[i]),&flag,s_curr,s_count);

		//if flag=1||2, call recursive littlearray1 and store it
		if(flag==1||flag==2)
		{
			temp = syntaxTreeBuilder((tokenarr->list[i]).littleArray1, s_curr,s_count);
			//if Root->rightchild is still NULL, store it there only,
			if(synRoot->rightchild == NULL)
			{
				synRoot->rightchild = temp;
			}
			else
			{
				//otherwise store it in root->rightchild->leftchild
				synRoot->rightchild->leftchild = temp;
			}
		}

		if(flag==2||flag==3)
		{
			//if flag=2||3, call recursive littleArray2 and store it in root->rightchild->rightchild
			temp = syntaxTreeBuilder((tokenarr->list[i]).littleArray2, s_curr,s_count);
			synRoot->rightchild->rightchild = temp;
		}

	}

	//return final root
	return synRoot;
}


// nullable ============================================================================================================
// function to check where the node is nullable or not
void isnullable(struct syntaxNode *node)
{
	// true if node labelled epsilon
	if(node->data == 'e')
		{
			node->nullable = 1;
		}
	// true if a node labelled *
	else if(node->data == '*')
		{
			node->nullable = 1;
		}
	// for a node labelled c1.c2 nulable(c1)and nullable(c2)
	else if(node->data == '.')
		{
			node->nullable = (node->leftchild->nullable)&&(node->rightchild->nullable);
		}
	// for a node labelled c1|c2 nulable(c1) or nullable(c2)
	else if(node->data == '|')
		{
			node->nullable = ((node->leftchild->nullable)||(node->rightchild->nullable));
		}
	// for a node labelled  with i not nullable
	else
		{
			node->nullable = 0;
		}
}

// To set the nullable of each node
// tree is being parsed in LVR manner
void nullable (struct syntaxNode *synRoot)
{
	if(synRoot == NULL)
		return;
	//L
	nullable(synRoot->leftchild);
	//V
	nullable(synRoot->rightchild);
	//R
	isnullable(synRoot);

}// end of Nullable
//nullable ==============================================================================================================

//FIRSTPOS and LASTPOS +++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

void FLpos(struct syntaxNode *node,int s_count)
{

	int i=0;
	// FIRSTPOS is NULL if node labelled 'e' and if leaf labeled with position i then  firstpos =i and lastpos =i
	// Already implented during syntax tree creation.

	// if a node labelled '|' ; fisrtpos is fp(c1) U fp(c2) ; lastpos is lp(c1) U lp(c2)
	if(node->data == '|')
		{
			int *fp = Union(node->leftchild->firstpos.poslist,node->rightchild->firstpos.poslist,s_count,node->leftchild->firstpos.poscount,node->rightchild->firstpos.poscount);
			int *lp = Union(node->leftchild->lastpos.poslist,node->rightchild->lastpos.poslist,s_count,node->leftchild->lastpos.poscount,node->rightchild->lastpos.poscount);
			for(i=0;i<s_count;i++)
			{
				if(fp[i] == 1)
					node->firstpos.poslist[node->firstpos.poscount++]=i+1;
				if(lp[i] == 1)
					node->lastpos.poslist[node->lastpos.poscount++] =i+1;
			}

		}
	// if a node labelled '*' ; firstpos id fp(c1) ; lastpos is lp(c1)
	else if(node->data == '*')
	{
		for(i=0;i<node->leftchild->firstpos.poscount;i++)
		{
			node->firstpos.poslist[node->firstpos.poscount++]=node->leftchild->firstpos.poslist[i];
		}
		for(i=0;i<node->leftchild->lastpos.poscount;i++)
		{
			node->lastpos.poslist[node->lastpos.poscount++]=node->leftchild->lastpos.poslist[i];
		}
	}

	// if a node labelled '.'
	// FIRSTPOS;
	/*	if (nullable(c1))
			firstpos = fp(c1) U fp(c2)
		else
			firstpos = fp(c1)
	*/
	// LASTPOS;
	/*
		if(nullable(c2))
			lastpos = lp(c1) U lp(c2)
		else
			lastpos = lp(c2)
	*/
	else if(node->data == '.')
	{
		if(node->leftchild->nullable)
		{
			int *fp = Union(node->leftchild->firstpos.poslist,node->rightchild->firstpos.poslist,s_count,node->leftchild->firstpos.poscount,node->rightchild->firstpos.poscount);
			for(i=0;i<s_count;i++)
			{
				if(fp[i] == 1)
					node->firstpos.poslist[node->firstpos.poscount++]=i+1;
			}
		}
		else
		{
			for(i=0;i<node->leftchild->firstpos.poscount;i++)
			{
				node->firstpos.poslist[node->firstpos.poscount++]=node->leftchild->firstpos.poslist[i];
			}

		}
		if(node->rightchild->nullable)
		{
			int *lp = Union(node->leftchild->lastpos.poslist,node->rightchild->lastpos.poslist,s_count,node->leftchild->lastpos.poscount,node->rightchild->lastpos.poscount);
			for(i=0;i<s_count;i++)
			{
				if(lp[i] == 1)
					node->lastpos.poslist[node->lastpos.poscount++]=i+1;
			}

		}
		else
		{

			for(i=0;i<node->rightchild->lastpos.poscount;i++)
			{
				node->lastpos.poslist[node->lastpos.poscount++]=node->rightchild->lastpos.poslist[i];
			}

		}

	}

}

// To set the firstpos and lastpos of each node
// tree is being parsed in LVR manner
void firstpos_lastpos(struct syntaxNode *synRoot,int s_count)
{
	if(synRoot == NULL)
		return;
	//L
	firstpos_lastpos(synRoot->leftchild,s_count);
	//V
	firstpos_lastpos(synRoot->rightchild,s_count);
	//R
	FLpos(synRoot,s_count);
}


//FIRSTPOS and LASTPOS ++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

//function to print the syntax tree
void printSyntaxTree(struct syntaxNode *synRoot)
{
	int i;
	//print recursivly with vlr rule with addresses
	if(synRoot==NULL)
		return;
	printf("\n=================================\n");
	printf("\nAddress: %ld",(long int)(synRoot));
	printf("\nData: %c",synRoot->data);
	printf("\nNullable: %d",synRoot->nullable);
	printf("\nFirstpos Length: %d",synRoot->firstpos.poscount);
	printf("\nFirstpos: ");
	for(i=0;i<synRoot->firstpos.poscount;i++)
		printf("%d,",synRoot->firstpos.poslist[i]);
	printf("\nLastpos Length: %d",synRoot->lastpos.poscount);
	printf("\nLastpos: ");
	for(i=0;i<synRoot->lastpos.poscount;i++)
		printf("%d,",synRoot->lastpos.poslist[i]);

	printf("\nLeft child: %ld",(long int)(synRoot->leftchild));
	printf("\nRight child: %ld",(long int)(synRoot->rightchild));

	printf("\n=================================\n");

	printSyntaxTree(synRoot->leftchild);
	printSyntaxTree(synRoot->rightchild);


}



void saveSyntaxTreeRecursive(struct syntaxNode *synRoot, FILE *fpsyntax)
{
	int i;
	//print recursivly with vlr rule with addresses
	if(synRoot==NULL)
		return;
	fprintf(fpsyntax,"%ld\n",(long int)(synRoot));//node address
	fprintf(fpsyntax,"%c\n",synRoot->data);//node data
	fprintf(fpsyntax,"%d\n",synRoot->nullable);//node is nullable
	//fprintf(fpsyntax,"%d\n",synRoot->firstpos.poscount);//firstpos length
	for(i=0;i<synRoot->firstpos.poscount;i++)
		fprintf(fpsyntax,"%d,",synRoot->firstpos.poslist[i]);//firstpos csv
	//fprintf(fpsyntax,"\n%d\n",synRoot->lastpos.poscount);//lastpos length
	fprintf(fpsyntax,"\n");
	for(i=0;i<synRoot->lastpos.poscount;i++)
		fprintf(fpsyntax,"%d,",synRoot->lastpos.poslist[i]);//lastpos csv

	fprintf(fpsyntax,"\n%ld ",(long int)(synRoot->leftchild));//left child address
	fprintf(fpsyntax,"%ld\n",(long int)(synRoot->rightchild));//right child address

	//recursion call
	saveSyntaxTreeRecursive(synRoot->leftchild,fpsyntax);
	saveSyntaxTreeRecursive(synRoot->rightchild,fpsyntax);
}

void saveSyntaxTree(struct syntaxNode *synRoot)
{
	FILE *fp;
	fp=fopen("stree.txt","w");
	if(fp==NULL)
	{
		//printf("Syntax tree file open failed!\n");
		return;
	}
	//printf("\nSaving Syntax Tree to file..\n");
	saveSyntaxTreeRecursive(synRoot, fp);
	fprintf(fp,"$&$\n");
	//fclose(fp);
}

//syntax tree===========================================================================================================

//followpos calculation=================================================================================================
	/*
		RULES:
		{i, j} * {a, b}                      .
			   |  			    			/ \
			   |			  			   /   \
			   |                      	  /     \
			   C                 	 C1{i, j} {a, b}C2

		follopos(i) = {a, b}		followpos(i) = {a, b}
		followpos(j) = {a, b}		followpos(j) = {a, b}
	*/

struct followpos_matrix{
	int *set;
	int setCount;

	//to store followpos....
};

struct followpos_matrix *initFollowposMatrix(int symbolcount)
{
	symbolcount = symbolcount + 1;
	struct followpos_matrix *p = (struct followpos_matrix *)malloc(symbolcount * sizeof(struct followpos_matrix));
	int i;

	for( i = 0; i < symbolcount; i++ ) p[i].setCount = 0;	
	return p;
}


void printFollowpos(struct followpos_matrix *fp, int symbolcount)
{
	FILE *kx=fopen("followpos.txt","w");
	int i, j, k, tx, temp;
	//printf("\n------CALCULATED FOLLOWPOS: \n");
	fprintf(kx, "%d\n", symbolcount);
	for( i = 1; i <= symbolcount; i++)
	{
		//printf("fp(%d) = { ", i);
		//Sorting followpos
		for(j=0;j<fp[i].setCount-1;j++)
		{
			tx=j;
			for(k=j+1;k<fp[i].setCount;k++)
			{
				if(fp[i].set[tx]>fp[i].set[k])
					tx=k;
			}
			temp=fp[i].set[tx];
			fp[i].set[tx]=fp[i].set[j];
			fp[i].set[j]=temp;
		}
		//-----------------		
		for( j = 0; j < fp[i].setCount; j++ )
		{
			//printf("%d, ", fp[i].set[j]);
			fprintf(kx, "%d ", fp[i].set[j]);
		}
		//printf("}\n");
		fprintf(kx,"\n");
	}
	//printf("----------------------------------------------------------\n");
	fclose(kx);
}

int isDuplicate(int *a, int l, int k)
{
	int i;
	for( i = 0; i < l; i++ ){
		if( a[i] == k ) return 1;
	}
	return 0;
}

void assignFollowpos(int *a, int *b, int c1, int c2, struct followpos_matrix *fp, int symbolcount)
{
	int i, j, t;
	if( c1 == 0 ) return;

	for( i = 0; i < c1; i++ ){
		int *c = (int *)malloc(symbolcount * sizeof(int));
		t = 0;
		for( j = 0; j < fp[a[i]].setCount; j++ ) c[t++] = fp[a[i]].set[j];

		for( j = 0; j < c2; j++ ){
			//printf("%d %d %d\n", a[i], b[j], t);
			if( !isDuplicate(c, t, b[j]) ){
				c[t++] = b[j];
				fp[a[i]].setCount++;
			}
		}
		fp[a[i]].set = c;
	}
}

void calculateFollowpos(struct syntaxNode *root, int symbolcount, struct followpos_matrix *fp)
{
	//tree is traversed in VLR manner...
	if( root == NULL ) return;

	if( root->data == '.' ){
		assignFollowpos(root->leftchild->lastpos.poslist, root->rightchild->firstpos.poslist, root->leftchild->lastpos.poscount, root->rightchild->firstpos.poscount, fp, symbolcount);
	}

	if( root->data == '*' ){
		assignFollowpos(root->firstpos.poslist, root->lastpos.poslist, root->firstpos.poscount, root->lastpos.poscount, fp, symbolcount);
	}
	calculateFollowpos(root->leftchild, symbolcount, fp);
	calculateFollowpos(root->rightchild, symbolcount, fp);
}
//followpos calculation end=============================================================================================


//transition table calculation==========================================================================================
char *initSymbolArray(int symbolcount)
{
	symbolcount = symbolcount + 1;
	char *t = (char *)malloc(symbolcount * sizeof(char));
	return t;
}

void printSymbolTable(char *st, int symbolcount)
{
	int i;
	printf("\n-----------SYMBOL TABLE------------------------------\n");
	for( i = 1; i <= symbolcount; i++ ) printf("[%c,%d]  ", st[i], i);
	printf("\n-----------------------------------------------------\n");
}


void printDFA(struct dfaMatrix dfa[REMAX][REMAX], int symbolcount, int no_of_inputs, char *input, int _new_states)
{
	int i, j, k, t_symbocount = symbolcount;
	symbolcount *= 3;

	printf("\n--------------------DFA TABLE:\n");
	for( i = 1; i <= symbolcount; i++ ) printf(" ");
	for( i = 1; i <= no_of_inputs; i++ ){
		printf("|");
		for( j = 1; j <= symbolcount/2; j++ ) printf(" ");
		printf("%c", input[i-1]);
		for( j = 1; j <= symbolcount/2 - 1; j++ ) printf(" ");
	}
	printf("\n");

	for( i = 1; i <= (symbolcount*no_of_inputs); i++ ) printf("++");
	printf("\n");

	for( i = 1; i <= _new_states; i++ ){
		for( j = 0; j <= no_of_inputs; j++ ){
			printf("[");
			for( k = 1; k <= t_symbocount; k++ ) printf("%d,", dfa[i][j].set[k]);
			printf("]");
			for( k = 1; k <= (symbolcount - 2*t_symbocount)-2; k++ ) printf(" ");
			printf("|");
		}
		printf("\n");
	}
	printf("\n---------------------------------------------------------\n");
}

void printMappedDFA(struct dfaMatrix dfa[REMAX][REMAX], int new_states, int no_of_inputs, int symbolcount, char *inputs)
{
	int i, j, k;

	printf("\n--------------------DFA TABLE:\n");
	printf("   ");
	for( i = 1; i <= no_of_inputs; i++ ){
		printf("| %c ", inputs[i-1]);
	}
	printf("\n");

	for( i = 1; i <= 4*no_of_inputs; i++ ) printf("++");
	printf("\n");

	for( i = 1; i <= new_states; i++ ){
		for( j = 0; j <= no_of_inputs; j++ ){
			printf("%c  |", dfa[i][j].state);
		}
		printf("\n");
	}
	printf("\n---------------------------------------------------------\n");
}

void printObjectDFA(struct dfaObject* targetDFA)
{
    struct dfaMatrix (*dfa)[REMAX] = targetDFA->dfa;
    int symbolcount = targetDFA->symbolCount;
    int no_of_inputs = targetDFA->noOfInputs, _new_states = targetDFA->newStates;
    char* input = targetDFA->uniqueSymbols;
	int i, j, k, t_symbocount = targetDFA->symbolCount;
	symbolcount *= 3;

	printf("\n--------------------DFA TABLE----------------------------\n");
	for( i = 1; i <= symbolcount; i++ ) printf(" ");
	for( i = 1; i <= no_of_inputs; i++ ){
		printf("|");
		for( j = 1; j <= symbolcount/2; j++ ) printf(" ");
		printf("%c", input[i-1]);
		for( j = 1; j <= symbolcount/2 - 1; j++ ) printf(" "); 
	}
	printf("\n");

	for( i = 1; i <= (symbolcount*no_of_inputs); i++ ) printf("++");
	printf("\n");
	
	for( i = 1; i <= _new_states; i++ ){
		for( j = 0; j <= no_of_inputs; j++ ){
			printf("[");
			for( k = 1; k <= t_symbocount; k++ ) printf("%d,", dfa[i][j].set[k]);
			printf("]");
			for( k = 1; k <= (symbolcount - 2*t_symbocount)-2; k++ ) printf(" ");
			printf("|");
		}
		printf("\n");
	}
	printf("\n---------------------------------------------------------\n");
}

void printObjectMappedDFA(struct dfaObject* targetDFA)
{
    struct dfaMatrix (*dfa)[REMAX] = targetDFA->dfa;
    int symbolcount = targetDFA->symbolCount;
    int no_of_inputs = targetDFA->noOfInputs, new_states = targetDFA->newStates;
    char* inputs = targetDFA->uniqueSymbols;
	int i, j, k;

	printf("\n--------------------DFA TABLE----------------------------\n");
	printf("   ");
	for( i = 1; i <= no_of_inputs; i++ ){
		printf("| %c ", inputs[i-1]);
	}
	printf("\n");

	for( i = 1; i <= 4*no_of_inputs; i++ ) printf("++");
	printf("\n");

	for( i = 1; i <= new_states; i++ ){
		for( j = 0; j <= no_of_inputs; j++ ){
			printf("%c  |", dfa[i][j].state);
		}
		printf("\n");
	}
	printf("\n---------------------------------------------------------\n");
}

//an utility function, will be used in transition matrix calculation...
void constructSymbolTable(struct syntaxNode *root, char *st)
{
	if( root == NULL ) return;

	//traverse in LVR order to get the symbol order..
	constructSymbolTable(root->leftchild, st);
	constructSymbolTable(root->rightchild, st);

	//case: leaf node..
	if( root->leftchild == NULL && root->rightchild == NULL ){
		st[root->firstpos.poslist[0]] = root->data;
	}
}

int *move(int *a, int symbolcount, char ip, char *st)
{
	int i, j;
	int *b = (int *)malloc((symbolcount+1) * sizeof(int));
	for( i = 1; i <= symbolcount; i++ ){
		if( a[i] == 1 ){
			for(j = 1; j <= symbolcount; j++ ){
				if( st[j] == ip && j == i ) b[i] = 1;
			}
		} 
	}
	return b;
}

int *calculateTransition(int *a, struct dfaMatrix *bfp, int symbolcount)
{
	int *b = (int *)malloc((symbolcount+1) * sizeof(int));
	int i, j;

	for( i = 1; i <= symbolcount; i++ ){
		if( a[i] == 1 ){
			b = binMapUnion(b, bfp[i].set, symbolcount);
		}
	}

	return b;
}

int isNewState(struct dfaMatrix *s, int t, int *k, int symbolcount)
{
	int i, cnt = 0, j;
	for( i = 1; i <= symbolcount; i++ ){
		if( k[i] == 0 ) cnt++;
	}
	if( cnt >= symbolcount ) return 0;
	
	int *a = (int *)malloc((symbolcount+1) * sizeof(int));

	for( i = 0; i <= t; i++ ){
		cnt = 0;
		for( j = 1; j <= symbolcount; j++ ){
			if( ( s[i].set[j] ^ k[j] ) == 0 ) cnt++;
		}
		if( cnt >= symbolcount ) return 0;
	}
	return 1;
}

int isSame(int *a, int *b, int symbolcount)
{
	int i, cnt = 0;
	for( i = 1; i <= symbolcount; i++ ){
		if( a[i] == 0 ) cnt++;
	}
	if( cnt == symbolcount ) return -1;

	cnt = 0;
	for( i = 1; i <= symbolcount; i++ ){
		if( ( a[i] ^ b[i] ) == 0 ) cnt++;
	}
	if( cnt == symbolcount ) return 1;
	return 0;
}

void printMappedStates(struct dfaObject* targetDFA)
{
    struct dfaMatrix (*dfa)[REMAX] = targetDFA->dfa;
    int symbolcount = targetDFA->symbolCount;
    int new_states = targetDFA->newStates;
    int i, j;
	printf("\n--------------------MAPPED STATES------------------------\n");
	for( i = 1; i <= new_states; i++ ){
		printf(" %c = {", dfa[i][0].state);
		for( j = 1; j <= symbolcount; j++ ){
			if( dfa[i][0].set[j] == 1 ) printf("%d,", j);
		}
		printf("} ");
	}
	printf("\n---------------------------------------------------------\n");

}

void mapDFA(struct dfaMatrix dfa[REMAX][REMAX], int symbolcount, int no_of_inputs, int new_states)
{
	int i, j, k, t;
	char input = 'A';

	for( i = 1; i <= new_states; i++ ) dfa[i][0].state = input++;

	for( i = 1; i <= new_states; i++ ){
		for( j = 1; j <= no_of_inputs; j++ ){
			for( k = 1; k <= new_states; k++ ){
				t = isSame(dfa[i][j].set, dfa[k][0].set, symbolcount);
				if( t == -1 ) dfa[i][j].state = '_';
				else if( t == 1 ){
					dfa[i][j].state = dfa[k][0].state;
					break;
				}
			}
		}
	}
}

//an utility to mark initial and final states..
char *markFinal(struct dfaMatrix dfa[REMAX][REMAX], int *final_state_count, int new_states, int symbolcount)
{
	int i, j;
	char *f = (char *)malloc(new_states * sizeof(char));

	for( i = 1; i <= new_states; i++ ){
		for( j = 1; j <= symbolcount; j++ ){
			if( dfa[i][0].set[j] == 1 && j == (symbolcount) ){
				//printf("%c ", dfa[i][0].state);
				f[(*final_state_count)++] = dfa[i][0].state;
				break;
			}
		}
	}
	return f;
}

//an utility to save dfa in a text..
void saveDFA(struct dfaMatrix dfa[REMAX][REMAX], int new_states, int no_of_inputs, int final_state_count, char *inputs, char *final_states)
{
	int i, j;
	FILE *fp = fopen("dfa.txt", "w");
	if( fp == NULL ){
		//printf("Error! opening dfa.txt");
		return;
	}
	
	//printf("\nSaving DFA to file...\n");
	fprintf(fp, "%d", new_states);
	fputc(' ', fp);
	fprintf(fp, "%d", no_of_inputs);
	fputc(' ', fp);
	fprintf(fp, "%d", final_state_count);
	fputc('\n', fp);

	for( i = 1; i <= new_states; i++ ){
		fputc(dfa[i][0].state, fp);
		fputc(' ', fp);
	}
	fputc('\n', fp);
	
	for( i = 0; i < no_of_inputs; i++ ){
		fputc(inputs[i], fp);
		fputc(' ', fp);
	}
	fputc('\n', fp);
	
	for( i = 0; i < final_state_count; i++ ){
		fputc(final_states[i], fp);
		fputc(' ', fp);
	}
	fputc('\n', fp);
	
	for( i = 1; i <= new_states; i++ ){
		for( j = 1; j <= no_of_inputs; j++ ){
			fputc(dfa[i][j].state, fp);
			fputc(' ', fp);
		}
		fputc('\n', fp);
	}
	
}

void calculateTransitionTable(struct dfaMatrix dfa[REMAX][REMAX], struct syntaxNode *root, char *st, int symbolcount, struct followpos_matrix *fp, int no_of_inputs, int *ns, char *input)
{
	/*
		RULE:
			1. mark firstpos of root as new initial state
			2. calculate transition for new state for each input
			3. repeat step 2 until no new state is found
	*/
	struct dfaMatrix binFP[symbolcount+1], stack[REMAX];//stack to keep track of all the marked states...

	int i, j, top = -1, new_state_count;
	int prev_state;

	for( i = 1; i <= symbolcount; i++ ) binFP[i].set = toBinaryMap(fp[i].set, fp[i].setCount, symbolcount);

	(*ns)++;
	prev_state = (*ns);
	int *t = toBinaryMap(root->firstpos.poslist, root->firstpos.poscount, symbolcount);
	stack[++top].set = t;
	dfa[(*ns)][0].set = t;
	for( i = 1; i <= no_of_inputs; i++ ){
		int *a = move(dfa[(*ns)][0].set, symbolcount, input[i-1], st);
		int *b = calculateTransition(a, binFP, symbolcount);
		dfa[(*ns)][i].set = b;
	}
	
	while( 1 ){
		new_state_count = 0;

		for( i = 1; i <= no_of_inputs; i++ ){

			if( isNewState(stack, top, dfa[prev_state][i].set, symbolcount) ){
				stack[++top].set = dfa[prev_state][i].set;
				(*ns)++;
				dfa[(*ns)][0].set = dfa[prev_state][i].set;
				for( j = 1; j <= no_of_inputs; j++ ){
					int *a = move(dfa[(*ns)][0].set, symbolcount, input[j-1], st);
					int *b = calculateTransition(a, binFP, symbolcount);
					dfa[(*ns)][j].set = b;
				}
			}
			else new_state_count++;
		}

		if( new_state_count >= no_of_inputs && prev_state == (*ns) ) break;
		prev_state++;
	}

	mapDFA(dfa, symbolcount, no_of_inputs, (*ns));
	//printDFA(dfa, symbolcount, no_of_inputs, input, (*ns));
	//printMappedDFA(dfa, (*ns), no_of_inputs, symbolcount, input);
	int final_state_count = 0;
	char *final_states = markFinal(dfa, &final_state_count, (*ns), symbolcount);

	// printf("\n----Final states--------------------\n");
	// for( i = 0; i < final_state_count; i++ ) printf("%c ", final_states[i]);
	// printf("\n------------------------------------\n");

    // saveDFA(dfa, (*ns), no_of_inputs, final_state_count, input, final_states);
}
//transition table calculation end=====================================================================================================


// Main Function
/*
int main(int argc, char *argv[])
{
	int i;
	if(argc>2)
	{
		//printf("More than 1 argument\n");
		
		//for (i=0; i<argc; i++)
  		//printf("%s\n", argv[i]);
  
		return -2;
	}
	char REstring[REMAX];
    struct dfaMatrix dfa[REMAX][REMAX];
	strcpy(REstring,argv[1]);
	printf("\nSupported Characters: \n'a-d','f-z','A-Z',\n'e' for epsilon, '*','|','(',')'\n");
	printf("The RE entered:\n'%s'\n",REstring);

	int new_states = 0;
	char *st;
	struct followpos_matrix *fp;
	struct tokenArray *MainTokenArray=NULL;
	int symbolcountcurr = 0,symbolcount, uniqueSymbolCount;
	char uniqueSymbols[300];
    struct syntaxNode *syntaxRoot=NULL;

	if(normalizeRE(REstring))
	{
		printf("\nWrong Regular Expression! Program Terminated!\n");
		return -1;
	}
	printf("The normalized RE:\n'%s'\n",REstring);
	FILE *fpb=fopen("RE.txt","w");
	fprintf(fpb,"%s",REstring);
	symbolcount = countSymbols(REstring, &uniqueSymbolCount,uniqueSymbols);
	printf("The number of symbols is: %d\n",symbolcount);

	if(symbolcount<=1)
	{
		printf("\nRE empty!! Program Terminated!\n");
		return 0;
	}
	
	MainTokenArray = parseAndStoreTokens(REstring);
	printf("\nThe tokenised array:\n");
	printTokenArray(MainTokenArray);
	
	syntaxRoot = syntaxTreeBuilder(MainTokenArray,&symbolcountcurr,symbolcount);
	
	nullable(syntaxRoot);
	firstpos_lastpos(syntaxRoot,symbolcount);

	st = initSymbolArray(symbolcount);
	constructSymbolTable(syntaxRoot, st);
	printSymbolTable(st, symbolcount);

	printSyntaxTree(syntaxRoot);

	fp = initFollowposMatrix(symbolcount);
	calculateFollowpos(syntaxRoot, symbolcount, fp);
	printFollowpos(fp, symbolcount);
	saveSyntaxTree(syntaxRoot);
	calculateTransitionTable(dfa, syntaxRoot, st, symbolcount, fp, uniqueSymbolCount-1, &new_states, uniqueSymbols);
	return 1;
}//End of Main Function
*/

int re2dfa(char* originREString, struct dfaObject* targetDFA) {
	char reString[REMAX];
	int newStates = 0;
	char* st;
	struct followpos_matrix* fp;
	struct tokenArray* mainTokenArray = NULL;
	int symbolCountCurr = 0;
    int symbolCount, uniqueSymbolCount;
	char* uniqueSymbols = targetDFA->uniqueSymbols;
    struct syntaxNode* syntaxRoot = NULL;
    struct dfaMatrix (*dfa)[REMAX] = targetDFA->dfa;

	strcpy(reString, originREString);
	if (normalizeRE(reString)) {
		printf("\nWrong Regular Expression! Program Terminated!\n");
		return -1;
	}

	symbolCount = countSymbols(reString, &uniqueSymbolCount, uniqueSymbols);
	if (symbolCount <= 1) {
		printf("\nRE empty!! Program Terminated!\n");
		return -2;
	}
	
	mainTokenArray = parseAndStoreTokens(reString);
	
	syntaxRoot = syntaxTreeBuilder(
        mainTokenArray, &symbolCountCurr, symbolCount
    );
	nullable(syntaxRoot);
	firstpos_lastpos(syntaxRoot, symbolCount);

	st = initSymbolArray(symbolCount);
	constructSymbolTable(syntaxRoot, st);

	fp = initFollowposMatrix(symbolCount);
	calculateFollowpos(syntaxRoot, symbolCount, fp);
	calculateTransitionTable(
        dfa, syntaxRoot, st, symbolCount, fp,
        uniqueSymbolCount - 1, &newStates, uniqueSymbols
    );

    targetDFA->symbolCount = symbolCount;
    targetDFA->noOfInputs = uniqueSymbolCount - 1;
    targetDFA->newStates = newStates;

	return 0;
}

// End of Program
