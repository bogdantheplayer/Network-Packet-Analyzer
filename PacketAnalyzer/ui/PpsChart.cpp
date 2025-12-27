#include "PpsChart.h"
#include <QPainter>
#include <algorithm>

PpsChart::PpsChart(QWidget* parent) : QWidget(parent) {

    // Minimum size of the graph
    setMinimumHeight(90);
    setMinimumWidth(260);
}

void PpsChart::setCapacity(int n) {
    capacity = std::max(5, n);
    if (values.size() > capacity) {
        values = values.mid(values.size() - capacity);
    }
    update();
}

void PpsChart::clear() {
    values.clear(); // Remove all stored values
    update();  // Redraw empty graph
}

void PpsChart::pushValue(int pps) {
    if (pps < 0) pps = 0; // Do not allow negative values
    values.push_back(pps);  // Add new value
    if (values.size() > capacity) values.remove(0, values.size() - capacity);
    update();  // Redraw graph
}

void PpsChart::paintEvent(QPaintEvent*) {
    QPainter p(this);   // Painter used to draw the widget
    p.setRenderHint(QPainter::Antialiasing, true);

    p.fillRect(rect(), palette().base());  // Fill background

    const int w = width();
    const int h = height();

    // Margins around the plot area
    const int left = 34;
    const int right = 10;
    const int top = 10;
    const int bottom = 22;

    // Compute plotting rectangle
    QRect plot(left, top, w - left - right, h - top - bottom);
    if (plot.width() <= 10 || plot.height() <= 10) return;

    // Draw plot border
    p.drawRect(plot);

    // Draw title
    p.drawText(plot.adjusted(6, 2, -6, -2), Qt::AlignLeft | Qt::AlignTop, "PPS (last 60s)");

    if (values.isEmpty()) {
        p.drawText(plot.adjusted(6, 18, -6, -6), Qt::AlignLeft | Qt::AlignTop, "no data");
        return;
    }


    // Find maximum value
    int maxV = 1;
    for (int v : values) maxV = std::max(maxV, v);

    // Draw Y-axis labels
    p.drawText(2, plot.bottom(), "0");
    p.drawText(2, plot.top() + 10, QString::number(maxV));

    // Build polyline
    QPolygonF poly;
    const int n = values.size();
    poly.reserve(n);

    for (int i = 0; i < n; i++) {
        double x = plot.left() + (n == 1 ? 0.0 : (double)i * plot.width() / (double)(n - 1));
        double y = plot.bottom() - ((double)values[i] / (double)maxV) * plot.height();
        poly << QPointF(x, y);
    }

    p.drawPolyline(poly);  // Draw line

    // Draw label for the most recent value
    p.drawText(plot.adjusted(6, 0, -6, -6), Qt::AlignRight | Qt::AlignBottom,
               QString("now: %1").arg(values.back()));
}
