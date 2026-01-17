#include "widget.h"
#include "ui_widget.h"
#include <QMessageBox>

Widget::Widget(QWidget *parent)
    : QWidget(parent)
    , ui(new Ui::Widget)
{
    ui->setupUi(this);
    changeMoney(0);
}

Widget::~Widget()
{
    delete ui;
}

void Widget::changeMoney(int diff)
{
    if(money+diff<0)
    {
        QMessageBox mb;
        mb.warning(this,"Money Issue!","잔액이 부족합니다.");
    }
    money += diff;
    ui->lcdNumber->display(money);
    ui->pbCoffee->setEnabled(money>=100);
    ui->pbTea->setEnabled(money>=150);
    ui->pbMilk->setEnabled(money>=200);
    ui->pbReset->setEnabled(money>0);


}

void Widget::on_pb10_clicked()
{
    changeMoney(10);
}

void Widget::on_pb50_clicked()
{
    changeMoney(50);
}


void Widget::on_pb100_clicked()
{
    changeMoney(100);
}

void Widget::on_pb500_clicked()
{
    changeMoney(500);
}


void Widget::on_pbCoffee_clicked()
{
    changeMoney(-100);
}


void Widget::on_pbTea_clicked()
{
    changeMoney(-150);
}


void Widget::on_pbMilk_clicked()
{
    changeMoney(-200);
}

void Widget::on_pbReset_clicked()
{
    QMessageBox mb;
    if (money <= 0) {
        mb.warning(this, "Money Issue!", "잔액이 없습니다. 리셋할 수 없습니다.");
        return;
    }
    int coins[4] = {0}; // 500, 100, 50, 10 순서
    int values[4] = {500, 100, 50, 10};

    int remain = money;
    for (int i = 0; i < 4; ++i) {
        coins[i] = remain / values[i];
        remain %= values[i];
    }
    QString msg;
    msg += QString("거스름돈:\n");
    msg += QString("500원: %1개\n").arg(coins[0]);
    msg += QString("100원: %1개\n").arg(coins[1]);
    msg += QString("50원: %1개\n").arg(coins[2]);
    msg += QString("10원: %1개").arg(coins[3]);

    mb.information(this, "Change Info", msg);
    money = 0;
    changeMoney(0);
}
