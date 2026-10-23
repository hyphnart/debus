#pragma once
#include <QFutureWatcher>
#include <QProgressDialog>
#include <QTimer>
#include <QtConcurrent/QtConcurrentRun>
#include <QPointer>
#include <QWidget>
#include <atomic>
#include <memory>
#include <functional>
#include <algorithm>

// Single self-contained operation. Workers never touch widgets or the UI's QFile.
// Dialog is parented to owner; watcher is parented to owner. Completion callback runs on UI thread.
template <typename Result,typename Work,typename Finish>
void startBackgroundTask(QWidget *owner,const QString &title,Work work,Finish finish) {
    owner->setProperty("yas.activeTasks",owner->property("yas.activeTasks").toInt()+1);
    auto cancelled=std::make_shared<std::atomic_bool>(false);
    auto done=std::make_shared<std::atomic<qint64>>(0);
    auto total=std::make_shared<std::atomic<qint64>>(0);
    auto *dialog=new QProgressDialog(title,"Cancel",0,1000,owner);
    dialog->setWindowModality(Qt::NonModal);
    dialog->setMinimumDuration(0);
    dialog->setAutoClose(false);
    dialog->setAutoReset(false);
    auto *watcher=new QFutureWatcher<Result>(owner);
    auto *timer=new QTimer(watcher);
    timer->setInterval(90);
    QObject::connect(dialog,&QProgressDialog::canceled,owner,[cancelled]{
        cancelled->store(true,std::memory_order_relaxed);
    });
    QObject::connect(timer,&QTimer::timeout,owner,[dialog,done,total]{
        const qint64 t=total->load(std::memory_order_relaxed);
        const qint64 n=done->load(std::memory_order_relaxed);
        if(t>0)dialog->setValue(static_cast<int>(std::min(1000.0,1000.0*n/t)));
    });
    QObject::connect(watcher,&QFutureWatcher<Result>::finished,owner,
        [owner,watcher,timer,dialog,finish=std::move(finish)]() mutable {
            owner->setProperty("yas.activeTasks",std::max(0,owner->property("yas.activeTasks").toInt()-1));
            timer->stop();
            Result result=watcher->result();
            dialog->hide();
            dialog->deleteLater();
            watcher->deleteLater();
            finish(std::move(result));
        });
    timer->start();
    dialog->show();
    watcher->setFuture(QtConcurrent::run(
        [work=std::move(work),cancelled,done,total]() mutable -> Result {
            auto progress=[cancelled,done,total](qint64 n,qint64 t)->bool {
                done->store(n,std::memory_order_relaxed);
                total->store(t,std::memory_order_relaxed);
                return !cancelled->load(std::memory_order_relaxed);
            };
            return work(progress);
        }));
}
