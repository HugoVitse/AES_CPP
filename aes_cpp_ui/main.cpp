#include "mainwindow.h"
#include <QApplication>
#include <QMainWindow>
#include <QFileDialog>
#include <QDebug>
#include <QListWidget>
#include <QListWidgetItem>
#include <QLabel>
#include <QPushButton>
#include <QHBoxLayout>
#include <QWidget>
#include <QString>
#include <QStringList>
#include <QInputDialog>
#include <QMessageBox>
#include <QApplication>
#include "ui_mainwindow.h"
#include "encryptedfileregistry.h"

#include "AES_CPP/file.hpp"

void fillFiles(Ui::MainWindow ui, EncryptedFileRegistry registry){

    std::vector<std::string> listFiles = registry.getAllFiles();

    int count = ui.listWidget->count();
    for (int i = 0; i < count; ++i) {
        QListWidgetItem* item = ui.listWidget->item(i);

        // Supprimer le widget associé
        QWidget* widget = ui.listWidget->itemWidget(item);
        if (widget) {
            ui.listWidget->removeItemWidget(item);  // Détache du QListWidget
            delete widget;                           // Libère la mémoire du widget
        }

        delete item; // Supprime l'item lui-même
    }



    for (const std::string& stdFile : listFiles) {
        QString file = QString::fromStdString(stdFile);


        // 1. Crée un widget de ligne personnalisé
        QWidget* itemWidget = new QWidget();

        // 2. Crée les composants
        QLabel* label = new QLabel(file);
        QPushButton* button = new QPushButton("Déchiffrer");

        // 3. Layout horizontal
        QHBoxLayout* layout = new QHBoxLayout(itemWidget);
        layout->addWidget(label);
        layout->addStretch(); // pousse le bouton à droite
        layout->addWidget(button);
        layout->setContentsMargins(5, 2, 5, 2);  // marges internes

        itemWidget->setLayout(layout);


        QListWidgetItem* listItem = new QListWidgetItem();
        listItem->setSizeHint(itemWidget->sizeHint());
        // 5. Ajoute l'item et le widget au QListWidget

        ui.listWidget->addItem(listItem);
        ui.listWidget->setItemWidget(listItem, itemWidget);

        // 6. Connecte le bouton à une lambda utilisant std::string ou QString
        QObject::connect(button, &QPushButton::clicked, [file, ui]() {
            bool ok;
            QString text = QInputDialog::getText(nullptr, "Entrée requise",
                                                 "Entrez la clé de déchiffrement : \n" + file,
                                                 QLineEdit::Normal, "", &ok);
            if (ok && !text.isEmpty()) {
                std::string pathStr = file.toStdString();
                std::string keyStr = text.toStdString();

                AES_CPP::File file_2(pathStr, pathStr);
                AES_CPP::Key key(keyStr);

                EncryptedFileRegistry registry;
                try {
                    file_2.decode(&key);
                    registry.removeFile(pathStr);
                    QMessageBox::information(nullptr, "Déchiffrement réussi \n", "Fichier déchiffré avec succès");
                    ui.stackedWidget->setCurrentIndex(0);

                }
                catch (const std::exception& e) {
                     QMessageBox::critical(nullptr, "Erreur", "Fichier non déchiffré \n" + text);
                }


            }
        });
    }
}

int main(int argc, char *argv[])
{
    QApplication app(argc, argv);

    QMainWindow window;
    Ui::MainWindow ui;
    ui.setupUi(&window);
    EncryptedFileRegistry registry;




    // Connecter le bouton "Parcourir"
    QObject::connect(ui.pushButton, &QPushButton::clicked, [&]() {
        QString filePath = QFileDialog::getOpenFileName(&window, "Choisir un fichier", "", "Tous les fichiers (*)");
        if (!filePath.isEmpty()) {
            ui.lineEdit->setText(filePath);
            if(registry.contains(filePath.toStdString())){
                ui.pushButton_2->setText("Déchiffrer");

            }
        }
    });

    QObject::connect(ui.pushButton_3, &QPushButton::clicked, [&]() {
        fillFiles(ui, registry);
        ui.stackedWidget->setCurrentIndex(1);
    });
    QObject::connect(ui.pushButton_4, &QPushButton::clicked, [&]() {
        ui.stackedWidget->setCurrentIndex(0);
    });


    QObject::connect(ui.lineEdit, &QLineEdit::textChanged, &window, [&](const QString &text) {
        if(registry.contains(text.toStdString())) {
            ui.pushButton_2->setText("Déchiffrer");
        }
        else {
            ui.pushButton_2->setText("Chiffrer");
        }
    });


    // Connecter le bouton "Encrypter"
    QObject::connect(ui.pushButton_2, &QPushButton::clicked, [&]() {
        QString path = ui.lineEdit->text();
        QString keyString = ui.lineEdit_2->text();
        if (!path.isEmpty()) {
            std::string pathStr = path.toStdString();
            std::string keyStr = keyString.toStdString();

            AES_CPP::File file(pathStr, pathStr);
            AES_CPP::Key key(keyStr);

            if(registry.contains(pathStr)){
                file.decode(&key);
                registry.removeFile(pathStr);
                ui.pushButton_2->setText("Chiffrer");

            }
            else {
                AES_CPP::IV iv(AES_CPP::Utils::generateRandomIV());
                AES_CPP::Padding padding(AES_CPP::Padding::PKcs7);
                file.encode(&key, AES_CPP::ChainingMethod::GCM, &iv, &padding);
                registry.addFile(pathStr);
                ui.pushButton_2->setText("Déchiffrer");
            }


        }
    });

    // (Optionnel) Appliquer un style moderne
    app.setStyleSheet(R"(
        QPushButton {
            background-color: #2d89ef;
            color: white;
            padding: 6px;
            border-radius: 8px;
        }
        QPushButton:hover {
            background-color: #1e5fbf;
        }
        QLineEdit {
            padding: 5px;
            border: 1px solid #ccc;
            border-radius: 6px;
        }
    )");

    //window.setFixedSize(400, 150); // Fixer la taille si tu veux
    window.show();
    return app.exec();
}
