// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 The fprint-tpm-authenticator authors

#include <QApplication>
#include <QCommandLineParser>
#include <QDBusConnection>
#include <QDBusConnectionInterface>
#include <QDialog>
#include <QGraphicsOpacityEffect>
#include <QHBoxLayout>
#include <QIcon>
#include <QLabel>
#include <QLocale>
#include <QPainter>
#include <QPainterPath>
#include <QPropertyAnimation>
#include <QPushButton>
#include <QScreen>
#include <QTimer>
#include <QVBoxLayout>

namespace {
constexpr int kIconSize = 104;
constexpr int kMaxSiteLength = 253;
constexpr int kMatchedLingerMs = 700;
constexpr int kIdleExitMs = 60000;

enum State : uint { Waiting = 0, NoMatch = 1, Retry = 2, Matched = 3, Failed = 4 };
enum Operation : uint { Register = 0, SignIn = 1, Select = 2 };

struct Strings {
    QString title, registerFor, signInTo, selectFor, touch, retry, matched, failed, cancel;
    QString attemptsLeft1, attemptsLeftN;
};

Strings strings()
{
    if (QLocale().language() == QLocale::Azerbaijani) {
        return {QStringLiteral("Barmaq izi"),
                QStringLiteral("Passkey yaradılır:"),
                QStringLiteral("Daxil olunur:"),
                QStringLiteral("Təhlükəsizlik açarı seçilir:"),
                QStringLiteral("Barmaq izi sensoruna toxunun"),
                QStringLiteral("Barmağınızı qaldırıb yenidən toxunun"),
                QStringLiteral("Tanındı"),
                QStringLiteral("Tanınmadı. Sorğu rədd edildi"),
                QStringLiteral("Ləğv et"),
                QStringLiteral("Tanınmadı. 1 cəhd qaldı"),
                QStringLiteral("Tanınmadı. %1 cəhd qaldı")};
    }
    return {QStringLiteral("Fingerprint"),
            QStringLiteral("Create a passkey for"),
            QStringLiteral("Sign in to"),
            QStringLiteral("Use this security key for"),
            QStringLiteral("Touch the fingerprint sensor"),
            QStringLiteral("Lift your finger and touch the sensor again"),
            QStringLiteral("Recognized"),
            QStringLiteral("Not recognized. Request denied"),
            QStringLiteral("Cancel"),
            QStringLiteral("Not recognized. 1 attempt left"),
            QStringLiteral("Not recognized. %1 attempts left")};
}

const QColor kNegative(0xda, 0x44, 0x53);
const QColor kPositive(0x27, 0xae, 0x60);

QPixmap drawnFingerprint(int size, const QColor &color, qreal dpr)
{
    QPixmap pixmap(QSize(size, size) * dpr);
    pixmap.setDevicePixelRatio(dpr);
    pixmap.fill(Qt::transparent);
    QPainter painter(&pixmap);
    painter.setRenderHint(QPainter::Antialiasing);
    painter.setPen(QPen(color, size / 26.0, Qt::SolidLine, Qt::RoundCap));
    const QPointF centre(size * 0.5, size * 0.54);
    const qreal ridges[][4] = {{0.40, 0.44, 150, 240}, {0.33, 0.37, 120, 290},
                               {0.26, 0.30, 100, 300}, {0.19, 0.23, 60, 300},
                               {0.12, 0.155, 30, 300}, {0.05, 0.08, 0, 260}};
    for (const auto &r : ridges) {
        const QRectF box(centre.x() - r[0] * size, centre.y() - r[1] * size, 2 * r[0] * size,
                         2 * r[1] * size);
        painter.drawArc(box, int(r[2] * 16), int(r[3] * 16));
    }
    return pixmap;
}

QPixmap tinted(const QIcon &icon, int size, const QColor &color, qreal dpr)
{
    if (icon.isNull()) {
        return drawnFingerprint(size, color, dpr);
    }
    QPixmap pixmap = icon.pixmap(QSize(size, size), dpr);
    QPainter painter(&pixmap);
    painter.setCompositionMode(QPainter::CompositionMode_SourceIn);
    painter.fillRect(pixmap.rect(), color);
    return pixmap;
}

class PromptDialog : public QDialog
{
    Q_OBJECT

public:
    PromptDialog()
        : m_text(strings())
        , m_icon(QIcon::fromTheme(QStringLiteral("fingerprint-symbolic"),
                                  QIcon::fromTheme(QStringLiteral("auth-fingerprint-symbolic"))))
    {
        setWindowTitle(m_text.title);
        setWindowIcon(QIcon::fromTheme(QStringLiteral("fingerprint"), m_icon));
        setWindowFlag(Qt::WindowStaysOnTopHint);
        setWindowFlag(Qt::WindowContextHelpButtonHint, false);
        setFixedWidth(400);

        m_heading = new QLabel(this);
        m_site = new QLabel(this);
        m_glyph = new QLabel(this);
        m_status = new QLabel(this);
        for (QLabel *label : {m_heading, m_site, m_status}) {
            label->setTextFormat(Qt::PlainText); // untrusted input
            label->setAlignment(Qt::AlignCenter);
            label->setWordWrap(true);
        }
        m_glyph->setAlignment(Qt::AlignCenter);
        m_glyph->setFixedHeight(kIconSize + 8);

        QFont headingFont = font();
        headingFont.setPointSizeF(headingFont.pointSizeF() * 1.05);
        m_heading->setFont(headingFont);
        QFont siteFont = font();
        siteFont.setPointSizeF(siteFont.pointSizeF() * 1.45);
        siteFont.setBold(true);
        m_site->setFont(siteFont);
        m_site->setTextInteractionFlags(Qt::NoTextInteraction);
        QFont statusFont = font();
        statusFont.setPointSizeF(statusFont.pointSizeF() * 1.1);
        m_status->setFont(statusFont);
        m_status->setMinimumHeight(QFontMetrics(statusFont).height() + 6);

        auto *cancel = new QPushButton(m_text.cancel, this);
        cancel->setAutoDefault(false);
        cancel->setMinimumWidth(120);
        connect(cancel, &QPushButton::clicked, this, &PromptDialog::reject);
        auto *buttons = new QHBoxLayout;
        buttons->addStretch();
        buttons->addWidget(cancel);
        buttons->addStretch();

        auto *layout = new QVBoxLayout(this);
        layout->setContentsMargins(28, 24, 28, 22);
        layout->setSpacing(6);
        layout->addWidget(m_heading);
        layout->addWidget(m_site);
        layout->addSpacing(14);
        layout->addWidget(m_glyph);
        layout->addSpacing(8);
        layout->addWidget(m_status);
        layout->addSpacing(14);
        layout->addLayout(buttons);

        auto *effect = new QGraphicsOpacityEffect(m_glyph);
        m_glyph->setGraphicsEffect(effect);
        m_pulse = new QPropertyAnimation(effect, "opacity", this);
        m_pulse->setDuration(1400);
        m_pulse->setKeyValueAt(0.0, 1.0);
        m_pulse->setKeyValueAt(0.5, 0.45);
        m_pulse->setKeyValueAt(1.0, 1.0);
        m_pulse->setLoopCount(-1);
    }

    void begin(const QString &site, uint operation)
    {
        const QString shown = site.left(kMaxSiteLength);
        m_heading->setText(operation == Register ? m_text.registerFor
                           : operation == Select ? m_text.selectFor
                                                 : m_text.signInTo);
        m_site->setText(shown.isEmpty() ? QStringLiteral("?") : shown);
        setState(Waiting, 0);
    }

    void setState(uint state, int attemptsLeft)
    {
        QColor color = palette().color(QPalette::Highlight);
        QString text = m_text.touch;
        bool pulsing = true;
        switch (state) {
        case NoMatch:
            color = kNegative;
            text = attemptsLeft == 1 ? m_text.attemptsLeft1
                                     : m_text.attemptsLeftN.arg(qMax(0, attemptsLeft));
            break;
        case Retry:
            text = m_text.retry;
            break;
        case Matched:
            color = kPositive;
            text = m_text.matched;
            pulsing = false;
            break;
        case Failed:
            color = kNegative;
            text = m_text.failed;
            pulsing = false;
            break;
        default:
            break;
        }
        m_state = state;
        m_glyph->setPixmap(tinted(m_icon, kIconSize, color, devicePixelRatioF()));
        m_status->setText(text);
        QPalette statusPalette = m_status->palette();
        statusPalette.setColor(QPalette::WindowText,
                               state == Waiting || state == Retry
                                   ? palette().color(QPalette::WindowText)
                                   : color);
        m_status->setPalette(statusPalette);
        if (pulsing) {
            if (m_pulse->state() != QAbstractAnimation::Running) {
                m_pulse->start();
            }
        } else {
            m_pulse->stop();
            static_cast<QGraphicsOpacityEffect *>(m_glyph->graphicsEffect())->setOpacity(1.0);
        }
    }

    uint state() const { return m_state; }

    void present()
    {
        adjustSize();
        setFixedHeight(height());
        if (const QScreen *screen = QGuiApplication::primaryScreen()) {
            move(screen->availableGeometry().center() - rect().center());
        }
        show();
        raise();
        activateWindow();
    }

Q_SIGNALS:
    void cancelRequested();

public:
    void reject() override { Q_EMIT cancelRequested(); }

private:
    Strings m_text;
    QIcon m_icon;
    QLabel *m_heading, *m_site, *m_glyph, *m_status;
    QPropertyAnimation *m_pulse;
    uint m_state = Waiting;
};

class PromptService : public QObject
{
    Q_OBJECT
    Q_CLASSINFO("D-Bus Interface", "net.fpta.Prompt1")

public:
    explicit PromptService(PromptDialog *dialog)
        : m_dialog(dialog)
    {
        m_idle.setSingleShot(true);
        m_idle.setInterval(kIdleExitMs);
        connect(&m_idle, &QTimer::timeout, qApp, &QCoreApplication::quit);
        m_idle.start();
        connect(m_dialog, &PromptDialog::cancelRequested, this, [this] {
            if (m_current != 0) {
                Q_EMIT Cancelled(m_current);
            }
            hideNow();
        });
    }

public Q_SLOTS:
    Q_SCRIPTABLE uint Begin(const QString &site, uint operation)
    {
        m_idle.stop();
        m_current = m_next++;
        if (m_next == 0) {
            m_next = 1;
        }
        m_dialog->begin(site, operation);
        m_dialog->present();
        return m_current;
    }

    Q_SCRIPTABLE void SetState(uint id, uint state, int attemptsLeft)
    {
        if (id == m_current && id != 0) {
            m_dialog->setState(state, attemptsLeft);
        }
    }

    Q_SCRIPTABLE void End(uint id)
    {
        if (id != m_current || id == 0) {
            return;
        }
        m_current = 0;
        if (m_dialog->state() == Matched || m_dialog->state() == Failed) {
            QTimer::singleShot(kMatchedLingerMs, this, [this] {
                if (m_current == 0) {
                    hideNow();
                }
            });
        } else {
            hideNow();
        }
    }

Q_SIGNALS:
    Q_SCRIPTABLE void Cancelled(uint id);

private:
    void hideNow()
    {
        m_current = 0;
        m_dialog->hide();
        m_idle.start();
    }

    PromptDialog *m_dialog;
    QTimer m_idle;
    uint m_current = 0;
    uint m_next = 1;
};

int renderPreview(const QStringList &args)
{
    PromptDialog dialog;
    dialog.begin(args.value(2, QStringLiteral("github.com")), args.value(3, QStringLiteral("1")).toUInt());
    dialog.setState(args.value(0).toUInt(), args.value(4, QStringLiteral("2")).toInt());
    dialog.adjustSize();
    dialog.ensurePolished();
    return dialog.grab().save(args.value(1), "PNG") ? 0 : 1;
}

}

int main(int argc, char **argv)
{
    QApplication app(argc, argv);
    QApplication::setApplicationName(QStringLiteral("fpta-prompt"));
    QApplication::setDesktopFileName(QStringLiteral("fpta-prompt"));
    QApplication::setQuitOnLastWindowClosed(false);
    if (QIcon::themeName().isEmpty() || QIcon::themeName() == QLatin1String("hicolor")) {
        QIcon::setThemeName(QStringLiteral("breeze"));
    }

    QCommandLineParser parser;
    parser.setApplicationDescription(QStringLiteral("Fingerprint confirmation window for fptad."));
    parser.addHelpOption();
    QCommandLineOption preview(QStringLiteral("preview"),
                               QStringLiteral("Render STATE to a PNG file and exit."));
    parser.addOption(preview);
    parser.addPositionalArgument(QStringLiteral("args"), QStringLiteral("STATE FILE [SITE [OP [N]]]"));
    parser.process(app);
    if (parser.isSet(preview)) {
        return renderPreview(parser.positionalArguments());
    }

    QDBusConnection bus = QDBusConnection::sessionBus();
    if (!bus.isConnected()) {
        qCritical("fpta-prompt: no session bus");
        return 1;
    }
    PromptDialog dialog;
    PromptService service(&dialog);
    if (!bus.registerObject(QStringLiteral("/net/fpta/Prompt"), &service,
                            QDBusConnection::ExportScriptableSlots |
                                QDBusConnection::ExportScriptableSignals) ||
        !bus.registerService(QStringLiteral("net.fpta.Prompt"))) {
        qCritical("fpta-prompt: net.fpta.Prompt is already owned");
        return 1;
    }
    return app.exec();
}

#include "main.moc"
