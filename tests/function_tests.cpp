#include "FunctionAnalysisEngine.h"
#include <QCoreApplication>
#include <QDebug>
#include <cstdlib>
static void require(bool b,const char *msg) {if(!b){qCritical()<<"FAIL:"<<msg;std::exit(1);}}
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    DisassemblyReport input;
    input.instructions={
        {0x1000,"e8 0b 00 00 00","call","0x1010"},
        {0x1005,"c3","ret",""},
        {0x1006,"90","nop",""},
        {0x1007,"e8 f4 0f 00 00","call","0x2000"},
        {0x100c,"c3","ret",""},
        {0x1010,"90","nop",""},
        {0x1011,"c3","ret",""},
    };
    const auto result=FunctionAnalysisEngine::analyze(input);
    require(result.calls.size()==2,"two direct call edges");
    require(result.calls[0].callerRegion==0x1000,"first caller region");
    require(result.calls[0].target==0x1010 && result.calls[0].targetInWindow,"decoded target");
    require(result.calls[1].callerRegion==0x1006,"post-ret region");
    require(result.calls[1].target==0x2000 && !result.calls[1].targetInWindow,"external target");
    bool sawTarget=false,sawExternal=false;
    for(const auto &region:result.regions){
        if(region.entry==0x1010){sawTarget=true;require(region.directCallers==1,"call count");}
        if(region.entry==0x2000){sawExternal=true;require(!region.entryInWindow,"external region");}
    }
    require(sawTarget && sawExternal,"candidate regions");
    DisassemblyReport empty;
    require(FunctionAnalysisEngine::analyze(empty).regions.isEmpty(),"empty report");
    qInfo()<<"PASS: function regions and call edges";
    return 0;
}
