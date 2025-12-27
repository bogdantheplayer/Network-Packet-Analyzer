#pragma once
#include <QWidget>
#include <QVector>

class PpsChart : public QWidget {
    Q_OBJECT
public:
    explicit PpsChart(QWidget* parent = nullptr);  // Constructor

    void pushValue(int pps);  // Add a new PPS value
    void setCapacity(int n); // Set how many samples are kept in history
    void clear();  // Clear all stored samples

protected:
    void paintEvent(QPaintEvent* event) override;  // Qt calls this when the widget must be redrawn

private:
    int capacity = 60;  // How many points we keep in history
    QVector<int> values;  //  Stored PPS values


};
