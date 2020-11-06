#include "clang/Driver/Options.h"
#include "clang/AST/AST.h"
#include "clang/AST/ASTContext.h"
#include "clang/AST/ASTConsumer.h"
#include "clang/AST/RecursiveASTVisitor.h"
#include "clang/Frontend/ASTConsumers.h"
#include "clang/Frontend/FrontendActions.h"
#include "clang/Frontend/CompilerInstance.h"
#include "clang/Frontend/FrontendPluginRegistry.h"
#include "clang/Rewrite/Core/Rewriter.h"

// #define DEBUG_LEVEL
// #define SCILENT

#ifdef SCILENT
#define LOG(stmt) errs()<<""
#define OUTPUT(st) errs()<<""
#else
#define LOG(stmt) errs()<<stmt<< "\n"
#define OUTPUT(st) do{st->printPretty(errs(), NULL, PrintingPolicy(LangOptions())); errs()<<" ---Pretty---\n";} while(0)
#endif

#ifdef DEBUG_LEVEL
#define DEBUG_OUTPUT(st) OUTPUT(st)
#define DEBUG(stmt) errs() << stmt << "\n"
#else
#define DEBUG(stmt) errs()<<""
#define DEBUG_OUTPUT(st) errs()<<""
#endif

#define WARN(stmt) LOG("WARN: "<<stmt)

// add unlikely
#define LOADCHECKER "\n\n/*----load start----*/\n\tif( (get_flexible_len((void*)%s) == -1) ||\n\t (get_flexible_len((void*)%s) != 0 \\
&& get_flexible_len((void*)%s) != (size_t)%s)){\n\tBUG_ON(\"FLEXIBE ATTACKS\");\n\t}\n/*----load end----*/\n\n" 

#define LOADCHECKER_MULTI "\n\n/*----load start----*/\n\tif( (%s == -1) ||\n\t (%s != 0 \\
&& %s != %s)){\n\tBUG_ON(\"FLEXIBE ATTACKS\");\n\t}\n/*----load end----*/\n\n" 

#define LOADCHECKERIF "\n\n/*----load inside IfStmt without Compound----*/\n\tdo{\n\t\tif( (get_flexible_len(%s) == -1) \\
||\n\t (get_flexible_len(%s) != 0 \\ && get_flexible_len(%s) != %s)){\n\tBUG_ON(\"FLEXIBE ATTACKS\");\n\t}\n\t%s;}while(0)" 

#define STORER "\n\n/*----store start----*/ do{\n\t\t%s;\n\t\tstore_flexible_len((void*)%s,(size_t)%s);\n\t}while(0)"

#define STORER_MULTI "\n\n/*----store start----*/ do{\n\t\t%s;\n\t\tstore_flexible_len((void*)%s,(size_t)%s,%d,%d);\n\t}while(0);//"


using namespace std;
using namespace clang;
using namespace llvm;

typedef vector<string> AttributeSet;
typedef std::unordered_map<string, AttributeSet> StructMap;
typedef llvm::DenseMap<Decl *, Stmt *> DeclMap;

Rewriter rewriter;
bool changed;
StructMap SM;


// utility 
static void composeStructMap(string StructType, string AttriName){
    if(SM.find(StructType) == SM.end()){
        AttributeSet AS;
        AS.push_back(AttriName);
        SM.insert(make_pair(StructType, AS));
    }else{
        StructMap::iterator it;
        it = SM.find(StructType);
        it->second.push_back(AttriName);
    }
}

static AttributeSet findStructAttri(string StructType){
    StructMap::iterator it;
    it = SM.find(StructType);
    if(it == SM.end()){
        return AttributeSet(); 
    }else{
        return it->second;
    }
}

static int inline isFlexible(string StructType, string AttriName){
    // return 0 if not flexible
    // return index of vector if flexible
    AttributeSet found = findStructAttri(StructType);
    if(found.size() == 0)
        return 0;
    AttributeSet::iterator it = find(found.begin(), found.end(), AttriName);

    if(it == found.end())
        return 0;
    return distance(found.begin(), it) + 1;
}

class FlexibleFixerVisitor : public RecursiveASTVisitor<FlexibleFixerVisitor>{

private:
    ASTContext *astContext; 
    std::set<int64_t> trackedSet;
    DeclMap DSMap;

public:
    explicit FlexibleFixerVisitor(CompilerInstance *CI)
        : astContext(&(CI->getASTContext())) // initialize private members
    {
        rewriter.setSourceMgr(astContext->getSourceManager(),
            astContext->getLangOpts());
        changed = false;

        composeStructMap("tester","len");
        composeStructMap("tester","llen");
        composeStructMap("probe_resp","len");
        composeStructMap("devlink_fmsg_item", "len"); //
        composeStructMap("vport_portids","n_ids"); //
        composeStructMap("iwl_wipan_noa_data","length"); //
        composeStructMap("xfrm_replay_state_esn", "bmp_len");
        composeStructMap("ieee80211_mgd_assoc_data","ie_len"); //
        composeStructMap("ieee80211_mgd_assoc_data","ssid_len"); //
        composeStructMap("ieee80211_mgd_assoc_data","fils_kek_len"); //
        composeStructMap("dccp_service_list","dccpsl_nr"); //
        composeStructMap("nfc_evt_transaction","params_len");
        composeStructMap("nfc_evt_transaction","aid_len");
        composeStructMap("unix_address","len"); //
        composeStructMap("xfrm_algo","alg_key_len"); //
        composeStructMap("sctp_chunks_param","param_hdr.length");
        composeStructMap("l2tp_session","cookie_len"); //
        composeStructMap("l2tp_session","peer_cookie_len");
        composeStructMap("raw_data","len"); //
        composeStructMap("xfrm_algo_auth","alg_key_len"); //
        composeStructMap("ip_sf_socklist","sl_count");
        composeStructMap("xfrm_algo_aead","alg_key_len"); //
        composeStructMap("cfg80211_bss_ies","len"); //
        composeStructMap("inotify_event_info","name_len"); //
        composeStructMap("n_hdlc_buf","count"); //
        composeStructMap("sw_flow_actions","actions_len"); //
        composeStructMap("mgmt_rp_read_local_oob_ext_data","eir_len"); // 2
        composeStructMap("xfrm_sec_ctx","ctx_len"); //
        composeStructMap("ieee80211_mgd_auth_data","data_len"); //
        composeStructMap("cn_msg","len"); // 1 2 3

        // FIXME: data flow to support this
        // composeStructMap("packet","length"); discard this

        // vmalloc
        // composeStructMap("nft_set","dlen");

    }
    // bool VisitFunctionDecl(FunctionDecl *func);
    bool VisitStmt(Stmt *st);
    Stmt *findParents(clang::Stmt& stmt);
    bool InstrumentStore(Stmt *st, string StructBase, string SizeVar, int size, int index);
    bool InstrumentLoadChecker(Stmt *st, string StructExpr, string SizeVar, int size, int index);
    bool BinaryOperatorHandler(BinaryOperator *BP);
    bool MemberExprHandler(MemberExpr *MExpr, string &StructType, string &BaseStruct, string &str);
    void StmtHandler(Stmt *st);
    void ExprHandler(Expr *expr);
    DeclRefExpr *FindDecl(Expr *expr);
    SourceLocation findSemiAfterLocation(SourceLocation loc);
    SourceLocation findLocationAfterSemi(SourceLocation loc);
    SourceLocation findSemiBeforeExpr(SourceLocation loc);
    string GetPretty(Expr *expr);
    string GetPretty(Stmt *stmt);
    string GetFilename();
};

string FlexibleFixerVisitor::GetFilename(){
    
    FileID id = rewriter.getSourceMgr().getMainFileID();
    return rewriter.getSourceMgr().getFilename(rewriter.getSourceMgr().getLocForStartOfFile(id));
}

Stmt* FlexibleFixerVisitor::findParents(clang::Stmt& stmt)
{
    auto it = astContext->getParents(stmt).begin();
    if(it == astContext->getParents(stmt).end())
        return nullptr;

    const Stmt *aStmt = it->get<Stmt>();
    if(!aStmt){
        // try to get decl
        const Decl *aDecl = it->get<Decl>();

        if(!aDecl)
            return nullptr;
        DEBUG("We found DECL when looking for parents");
        DeclMap::iterator it = DSMap.find(aDecl);
        if(it == DSMap.end()){
            // didn't find a Stmt related with this decl
            WARN("Cannot handle this: "<< GetFilename());
            return nullptr;
        }

        aStmt = it->second;
        // DEBUG_OUTPUT(cast<VarDecl>(aDecl)->getInit());
        // auto DeclIt = astContext->getParents(aDecl).begin();
        // if(DeclIt == astContext->getParents(aDecl).end())
        //     return nullptr;

        // aStmt = DeclIt->get<Stmt>();
    }
    if(aStmt){
        DEBUG("This is "<<aStmt->getStmtClassName());
        DEBUG_OUTPUT(aStmt);
        DEBUG("RETURN IN FIND PARENTS");
        return const_cast<Stmt*>(aStmt);
    }
    return nullptr;
}


bool FlexibleFixerVisitor::InstrumentStore(Stmt *st, string StructBase, string SizeVar, int size, int index){

    if(!StructBase.size() || !SizeVar.size())
        return false;

    DEBUG("Instrumenting Store.");

    Stmt *pStmt = findParents(*st);

    if(pStmt){

        Stmt *ppStmt = findParents(*pStmt);
        // TODO: if store inside loop
        if( ppStmt 
                && (dyn_cast<ForStmt>(ppStmt) || dyn_cast<WhileStmt>(ppStmt) || dyn_cast<DoStmt>(ppStmt))){

            WARN(GetFilename() << " : This is going to be wrong: Store in the loop's condition ");
            WARN(GetPretty(ppStmt));
            return false;
        }
    }

    // just do while

    // SourceManager &SM = rewriter.getSourceMgr();
    // LOG("Sourcerange isvaild "<<SR.isValid() << " " << SR.printToString(SM));
    

    // SourceLocation loc = SR.getBegin();
    // LOG("is Maco id? " << loc.isMacroID());

    // LOG("at the end? " << Lexer::isAtEndOfMacroExpansion(loc, SM,
    //                                         rewriter.getLangOpts(), &loc));

    // SourceLocation EndLoc = Lexer::getLocForEndOfToken(loc, 0, SM, rewriter.getLangOpts());
    // string test = Lexer::getSourceText(CharSourceRange::getTokenRange(loc, EndLoc), SM, rewriter.getLangOpts());
    // LOG("String : "<< test);


    string Src = GetPretty(dyn_cast<Expr>(pStmt));
    SourceRange SR = pStmt->getSourceRange();

    char code[0x400] = "";
    snprintf(code, 0x400, STORER_MULTI, Src.c_str(), StructBase.c_str(), SizeVar.c_str(), size, index);
    rewriter.ReplaceText(SR,  code);
    changed |= true;
    return true;

}

bool FlexibleFixerVisitor::InstrumentLoadChecker(Stmt *st, string StructExpr, string SizeVar, int size, int index){

    if(!StructExpr.size() || !SizeVar.size())
        return false;

    DEBUG("Instrumenting Load Checker.");

    Stmt *pStmt = findParents(*st);
    Stmt *ppStmt;

    if(!pStmt) return false;

    // skip ImplicitCastExpr
    while(true){
        if(!pStmt) return false;
        if(!dyn_cast<ImplicitCastExpr>(pStmt)) break;
        pStmt = findParents(*pStmt);
    }    

    while(true){
        ppStmt = findParents(*pStmt);
        if(!ppStmt){
            WARN(GetFilename() << "Didn't Found the proper Stmt." );
            return false;
        }
        // if(dyn_cast<BinaryOperator>(pStmt)){
        //     BinaryOperator *BP = dyn_cast<BinaryOperator>(pStmt);
        //     if(BP->getOpcode() == BO_Assign)
        //         break;
        // }

        // if(dyn_cast<IfStmt>(ppStmt) || dyn_cast<ForStmt>(ppStmt)
        //         || dyn_cast<CompoundStmt>(ppStmt))

        // make it outside anyway
        if(dyn_cast<CompoundStmt>(ppStmt))
            break;

        pStmt = ppStmt;
    }


    if(dyn_cast<IfStmt>(ppStmt)){
        // discard this. load could be happening in if's condition.
        // string Src = GetPretty(pStmt);
        // SourceRange SL = pStmt->getSourceRange();
        // char code[0x400];
        // snprintf(code, 0x400, LOADCHECKERIF, StructExpr.c_str(),
        //             StructExpr.c_str(), SizeVar.c_str(), Src.c_str());
        // rewriter.ReplaceText(SL, code);
        // return true;

        // put on the head anyway.

    }


    if(dyn_cast<ForStmt>(ppStmt)){
        // pStmt = ppStmt;
    }

    SourceRange SR = pStmt->getSourceRange();
    char get_len[0x100] = "";
    char code[0x400] = "";

    snprintf(get_len, 0x100, "get_flexible_len((void*)%s,%d,%d)", StructExpr.c_str(), size, index);


    snprintf(code, 0x400, LOADCHECKER_MULTI,  get_len, get_len, get_len, SizeVar.c_str());

    rewriter.InsertTextBefore(SR.getBegin(), code);
    changed |= true;
    return true;
}

SourceLocation FlexibleFixerVisitor::findSemiAfterLocation(SourceLocation loc) {
    SourceManager &SM = rewriter.getSourceMgr();
    if (loc.isMacroID()) {
        if (!Lexer::isAtEndOfMacroExpansion(loc, SM,
                                            rewriter.getLangOpts(), &loc))
            return SourceLocation();
    }
    loc = Lexer::getLocForEndOfToken(loc, /*Offset=*/0, SM,
                                       rewriter.getLangOpts());

    // Break down the source location.
    std::pair<FileID, unsigned> locInfo = SM.getDecomposedLoc(loc);

    // Try to load the file buffer.
    bool invalidTemp = false;
    StringRef file = SM.getBufferData(locInfo.first, &invalidTemp);
    if (invalidTemp){
        return SourceLocation();
    }

    const char *tokenBegin = file.data() + locInfo.second;

    // Lex from the start of the given location.
    Lexer lexer(SM.getLocForStartOfFile(locInfo.first),
                  rewriter.getLangOpts(),
                  file.begin(), tokenBegin, file.end());
    Token tok;
    lexer.LexFromRawLexer(tok);
    if (tok.isNot(tok::semi)){
        return findSemiAfterLocation(tok.getLocation());
    }

    return tok.getLocation();
}

SourceLocation FlexibleFixerVisitor::findLocationAfterSemi(SourceLocation loc){
    SourceLocation SemiLoc = findSemiAfterLocation(loc);
    if (SemiLoc.isInvalid())
        return SourceLocation();
    return SemiLoc.getLocWithOffset(1);
}

SourceLocation FlexibleFixerVisitor::findSemiBeforeExpr(SourceLocation loc){
    int count = 0;

    SourceLocation SemiLoc = findLocationAfterSemi(loc);
    if(SemiLoc.isInvalid())
        return SourceLocation();

    while(count < 30){
        count ++;
        SourceLocation TmpLoc = loc.getLocWithOffset(-count);
        if(TmpLoc.isInvalid())
            return SourceLocation();
        SourceLocation LastSemiLoc = findLocationAfterSemi(TmpLoc);
        if(!LastSemiLoc.isInvalid() && LastSemiLoc != SemiLoc){
            DEBUG("We Got This");
            return LastSemiLoc;
        }
    }
    DEBUG("No we didn't");
    return SourceLocation();
}
 
// bool FlexibleFixerVisitor::VisitFunctionDecl(FunctionDecl *func) {

//     return true;
// }

DeclRefExpr *FlexibleFixerVisitor::FindDecl(Expr *expr){
    DeclRefExpr * re;
    if(dyn_cast<DeclRefExpr>(expr)){
        return dyn_cast<DeclRefExpr>(expr);
    }else if(MemberExpr *Mexpr = dyn_cast<MemberExpr>(expr)){
        return FindDecl(Mexpr->getBase());
    }else if(ImplicitCastExpr *ICExpr = dyn_cast<ImplicitCastExpr>(expr)){
        return FindDecl(ICExpr->getSubExpr());
    }else{
        // what the hell it this
        // outs() << "Encounting some error, cannot handle this\n";
        // OUTPUT(expr);
        // outs() << "\n";
        exit(-1);
        return re;
    }
}

string FlexibleFixerVisitor::GetPretty(Expr *expr){
    string Buf;
    raw_string_ostream TempOut(Buf);
    expr->printPretty(TempOut,NULL, PrintingPolicy(LangOptions()));
    return Buf;
}

string FlexibleFixerVisitor::GetPretty(Stmt *stmt){
    string Buf;
    raw_string_ostream TempOut(Buf);
    stmt->printPretty(TempOut,NULL, PrintingPolicy(LangOptions()));
    return Buf;
}

void FlexibleFixerVisitor::StmtHandler(Stmt *st) {

    if(DeclStmt *Dstmt = dyn_cast<DeclStmt>(st)){
        DEBUG("Got DeclStmt " << GetPretty(Dstmt));

        for(auto decl : Dstmt->decls()){        
            if(Decl *aDecl = dyn_cast<Decl>(decl)){
                if(DSMap.find(aDecl) != DSMap.end()){
                    WARN(GetFilename() << " : Found 2 Stmt connect to the same Decl, "<<GetPretty(Dstmt));
                    return;
                }
                DSMap.insert(std::make_pair(aDecl, Dstmt));
            }
        }

    }else if(Expr *expr = dyn_cast<Expr>(st)){

        ExprHandler(expr);

    }else{
        // what the hell is this?
        #ifdef DEBUG_LEVEL
        outs() << "What the hell is this?\n";
        OUTPUT(st);
        outs() << "\n";
        #endif
    }
}

bool FlexibleFixerVisitor::BinaryOperatorHandler(BinaryOperator *BP){
    // check if assign to len
    if(BP->getOpcode() == BO_Assign){
        if(MemberExpr *MExpr = dyn_cast<MemberExpr>(BP->getLHS())){
            trackedSet.insert(MExpr->getID(*astContext));
            string LenExprStr;
            string BaseStruct;
            string StructType;
            if(MemberExprHandler(MExpr, StructType, BaseStruct, LenExprStr)){
                string SizeVarStr = GetPretty(BP->getRHS());
                DEBUG("Found Assignment: " << LenExprStr << " = " << SizeVarStr);


                string MName = MExpr->getMemberNameInfo().getAsString();
                int index = isFlexible(StructType, MName);
                if(index == 0)
                    return false;

                AttributeSet AS = findStructAttri(StructType);
                int size = AS.size();
                if(InstrumentStore(BP->getRHS(), BaseStruct, LenExprStr, size, index)){
                    LOG("Instrumented Store : " << GetFilename() <<":"<< StructType << " " << GetPretty(BP));
                    return true;
                }
            }
        }
    }
    return false;
}

bool FlexibleFixerVisitor::MemberExprHandler(MemberExpr *MExpr, string &StructType, string &BaseStruct, string &LenExprStr){
    // if(trackedSet.find(MExpr) != trackedSet.end()){
    //     return false;
    // }
    // trackedSet.insert(MExpr);

    DEBUG("ID: " << MExpr->getID(*astContext));

    string MName = MExpr->getMemberNameInfo().getAsString();
    DEBUG("Member name " << MName);

    if(auto *ICExpr = dyn_cast<ImplicitCastExpr>(MExpr->getBase())){
        StructType = ICExpr->getType().getAsString();
        
        // FIXME: parse type
        if(StructType.find(" *") == string::npos || StructType.find("struct ") == string::npos){
            DEBUG("Error in parsing Struct Type: " << StructType);
            return false;
        }
            
        int typeLen = StructType.find(" *") - strlen("struct ");
        StructType=StructType.substr(strlen("struct "), typeLen);
        DEBUG("Type: " << StructType);
        // if we got it
        LenExprStr = GetPretty(MExpr);
        BaseStruct = GetPretty(ICExpr);

        DEBUG("WE GOT BaseStruct " << BaseStruct);
        DEBUG("WE GOT LenExprStr " << LenExprStr);
        // check here

        int index = isFlexible(StructType, MName);
        if(index == 0)
            return false;
        
        AttributeSet AS = findStructAttri(StructType);
        int size = AS.size();

        DEBUG_OUTPUT(MExpr->getExprStmt());
        if(trackedSet.find(MExpr->getID(*astContext)) == trackedSet.end()){
            if(InstrumentLoadChecker(MExpr, BaseStruct, LenExprStr, size, index)){
                LOG("Instrumented Load : " << GetFilename() <<":"<< StructType << " " << GetPretty(MExpr));
                trackedSet.insert(MExpr->getID(*astContext));
                return true;
            }
        }
        DEBUG("Skip");
        return true;
    }
    return false;

}

void FlexibleFixerVisitor::ExprHandler(Expr *expr) {

    // do we need to add cookie after malloc
    // didn't found cast: drivers/firewire/nosy.c:packet_buffer_init
    if (CallExpr *call = dyn_cast<CallExpr>(expr)) {
        DEBUG("handling Callexpr");
        // DEBUG_OUTPUT(expr);

        Stmt *pStmt, *ppStmt;
        string StructType, Callee;
        AttributeSet AS;

        pStmt = call;

        while(true){
            ppStmt = findParents(*pStmt);

            if(!ppStmt || !dyn_cast<CastExpr>(ppStmt)){
                return;
            }
            // check if flexible struct
            StructType = dyn_cast<CastExpr>(ppStmt)->getType().getAsString();

            // parse it
            if(StructType.find(" *") == string::npos || StructType.find("struct ") == string::npos){
                DEBUG("Error in parsing Struct Type: " << StructType);
                return;
            }

            int typeLen = StructType.find(" *") - strlen("struct ");
            StructType=StructType.substr(strlen("struct "), typeLen);
            AS = findStructAttri(StructType);

            if(AS.size() != 0) // we found it
                break;
            pStmt = ppStmt;
        }

        // for(int i=0; i<call->getNumArgs(); i++){
        //     if(dyn_cast<Expr>(call->getArg(i))){
        //         // ExprHandler(dyn_cast<Expr>(call->getArg(i)));
        //         DEBUG_OUTPUT(call->getArg(i));
        //     }
        // }

        // kmalloc
        // kzalloc
        // krealloc

        // not to handle
        // kcalloc
        // vmalloc
        // kvmalloc
        // kvzalloc
        Callee = GetPretty(call->getCallee());

        Expr *sizeExpr;

        DEBUG("Found a Flexible Stucture Allocation : " << StructType << " " << GetPretty(call));

        if(Callee == "kmalloc" || Callee == "kzalloc"
                    || Callee == "krealloc"){

            // trying to replace the size
            sizeExpr = call->getArg(0);

        }else if(Callee == "devm_kzalloc" || Callee == "sock_kmalloc"){

            // trying to replace the size
            sizeExpr = call->getArg(1);

        }else if(Callee == "kvzalloc" || Callee == "kcalloc" 
                || Callee == "vmalloc" || Callee == "kvmalloc"){
            WARN(GetFilename() << " : Found vmalloc for "<< StructType << " " << GetPretty(call));
            return;
        }else{
            WARN(GetFilename() <<" : Found unrecongnized Flexible Allocation for "<< StructType << " " << GetPretty(call));
            return;
        }

        if(!sizeExpr)
            return;        

        
        string Src = GetPretty(sizeExpr);

        if(Src.size() == 0)
            return;

        // AS.size() * 0x8 + 0x8
        int size = 0x8*(AS.size()+1);
        char code[0x400] = "";
        
        // check if contain Macro
        SourceRange SR = dyn_cast<Stmt>(sizeExpr)->getSourceRange();

        // SourceLocation locBegin = SR.getBegin();
        // SourceLocation locEnd = SR.getEnd();
        // SourceLocation loc = locBegin.getLocWithOffset(0);
        // bool macro;
        // for(macro=false;loc != locEnd; loc=loc.getLocWithOffset(1)){
        //     macro |= loc.isMacroID();
        // }

        // LOG("is Maco id? " << macro);

        // if(macro){
            snprintf(code, 0x400, "%d+",size);
            rewriter.InsertText(SR.getBegin(), code);
        // }else{
        //     snprintf(code, 0x400, "%s+%d", Src.c_str(), size);
        //     rewriter.ReplaceText(SR, code);
        // }

        changed |= true;

        LOG("Instrumented Call : " << GetFilename() <<":"<< StructType << " " << GetPretty(call));

    }else if(BinaryOperator *BP = dyn_cast<BinaryOperator>(expr)){
        // DEBUG("handling BinaryOperator");
        DEBUG_OUTPUT(BP);
        BinaryOperatorHandler(BP);
    }else if(MemberExpr *MExpr = dyn_cast<MemberExpr>(expr)){
        string a,b,c;
        MemberExprHandler(MExpr, a, b, c);
    }
    
    return;

    // if(ImplicitCastExpr *ICExpr = dyn_cast<ImplicitCastExpr>(expr)){
    //     // DEBUG("handling ImplicitCastExpr");
    //     DEBUG_OUTPUT(ICExpr);

    //     // ExprHandler(ICExpr->getSubExpr());

    // }else if(DeclRefExpr *DRExpr = dyn_cast<DeclRefExpr>(expr)){
    //     // DEBUG("handling DeclRefExpr");
    //     DEBUG_OUTPUT(DRExpr);
    //     // string StructType = dyn_cast<VarDecl>(DRExpr->getDecl())->getType().getAsString();
    //     // LOG("Type: "<<StructType);
    // }
}
     
bool FlexibleFixerVisitor::VisitStmt(Stmt *st) {
    StmtHandler(st);
    return true;
}

class FlexibleFixerASTConsumer : public ASTConsumer {
private:
    FlexibleFixerVisitor *visitor; // doesn't have to be private

    void writeToFile(){
        return;
    }

    void BackupFile(string oldFile, string newFile){
        // rename(oldFile.c_str(), newFile.c_str());
        return;
    }
 
public:
    explicit FlexibleFixerASTConsumer(CompilerInstance *CI)
        : visitor(new FlexibleFixerVisitor(CI)) // initialize the visitor
        { }
 
    virtual void HandleTranslationUnit(ASTContext &Context) {
        visitor->TraverseDecl(Context.getTranslationUnitDecl());

        // Create an output file to write the updated code
        FileID id = rewriter.getSourceMgr().getMainFileID();
        string oldFileName = rewriter.getSourceMgr().getFilename(rewriter.getSourceMgr().getLocForStartOfFile(id));
        string filename = oldFileName + ".new";

        DEBUG("Writing to " << filename);

        // BackupFile(filename, backup);

        const RewriteBuffer *RewriteBuf = rewriter.getRewriteBufferFor(id);
        if(!changed){
            LOG("No change in this file: " << oldFileName);
        }
        if(!RewriteBuf){
            DEBUG("No rewriteBuf\n");
            return;
        }
        if(RewriteBuf->begin() == RewriteBuf->end()){
            DEBUG("Empty file");
            return;
        }

        std::error_code OutErrorInfo;
        std::error_code ok;
        llvm::raw_fd_ostream outFile(llvm::StringRef(filename),
            OutErrorInfo, llvm::sys::fs::F_None);
        if (OutErrorInfo == ok) {
            outFile << std::string(RewriteBuf->begin(), RewriteBuf->end());
            errs() << "Output file created: " << filename << "\n";
        } else {
            WARN("Could not create file : "<< filename);
        }
    }
};

class FlexiblePatcherAction : public PluginASTAction {
protected:
    unique_ptr<ASTConsumer> CreateASTConsumer(CompilerInstance &CI, StringRef file) {
        return make_unique<FlexibleFixerASTConsumer>(&CI);
    }
 
    bool ParseArgs(const CompilerInstance &CI, const vector<string> &args) {
        return true;
    }
};

static FrontendPluginRegistry::Add<FlexiblePatcherAction>
    X("-flexible-patcher-plugin", "Flexible Patcher Plugin");
