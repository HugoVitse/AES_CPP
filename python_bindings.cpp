#include "AES_CPP/block.hpp"
#include "AES_CPP/enums.hpp"
#include "AES_CPP/file.hpp"
#include "AES_CPP/key.hpp"

#include <pybind11/pybind11.h>
#include <pybind11/stl.h>

namespace py = pybind11;
using namespace AES_CPP;

PYBIND11_MODULE(aescpp, m) {
    m.doc() = "Python bindings for the AES_CPP library";

    // --- Class: File ---
    py::class_<File>(m, "File")
        .def(py::init<const std::string&, const std::string&>())
        .def("encode", &File::encode,
             py::arg("key"),
             py::arg("method"),
             py::arg("iv") = nullptr,
             py::arg("padding") = nullptr,
             py::arg("deprecated") = false,
             py::arg("meta") = true)
        .def("decode", &File::decode,
             py::arg("key"),
             py::arg("deprecated") = false);
             

    // --- Class: Key ---
    py::class_<AES_CPP::Key>(m, "Key")
        .def(py::init<std::string>());

    // --- Class: IV ---
    py::class_<AES_CPP::IV>(m, "IV")
        .def(py::init<std::string>());

    // --- Enum: ChainingMethod ---
    py::enum_<AES_CPP::ChainingMethod>(m, "ChainingMethod")
        .value("CBC", AES_CPP::ChainingMethod::CBC)
        .value("ECB", AES_CPP::ChainingMethod::ECB)
        .value("CTR", AES_CPP::ChainingMethod::CTR)
        .value("GCM", AES_CPP::ChainingMethod::GCM)
        .export_values();

    // --- Enum: Padding ---
    py::enum_<AES_CPP::Padding>(m, "Padding")
        .value("ZeroPadding", AES_CPP::Padding::ZeroPadding)
        .value("PKcs7", AES_CPP::Padding::PKcs7)
        .value("None_", AES_CPP::Padding::None)
        .export_values();
}
