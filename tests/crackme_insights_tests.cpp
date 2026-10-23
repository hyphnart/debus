#include "CrackmeInsights.h"
#include <QCoreApplication>
#include <QDebug>
#include <cstdlib>
int main(int argc,char **argv) {
    QCoreApplication app(argc,argv);
    DisassemblyReport r;
    r.instructions={
        {0x1000,"83 F8 02","cmp","eax, 2"},
        {0x1003,"74 05","je","0x100a"},
        {0x1005,"E8 00","call","0x1100"},
        {0x100a,"C3","ret",""},
        {0x1010,"FF D0","call","rax"}
    };
    auto clues=CrackmeInsights::scan(r);
    if(clues.size()!=2 || clues[0].category!="Compare + branch" ||
       clues[1].category!="Direct call" || clues[1].address!=0x1005) {
        qCritical()<<"Unexpected static crackme insights"<<clues.size();return EXIT_FAILURE;
    }
    DisassemblyReport empty;
    if(!CrackmeInsights::scan(empty).isEmpty())return EXIT_FAILURE;
    qInfo()<<"PASS: crackme insights local pattern analysis";
    return EXIT_SUCCESS;
}
