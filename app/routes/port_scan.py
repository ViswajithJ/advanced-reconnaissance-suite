from flask import Blueprint, render_template, jsonify

bp = Blueprint(
    "port_scan", __name__
)  # port_scan: name of blueprint; __name__: import name of blueprint's module

# to-do: update when port scan code is available
