from lib.pyt.core.ast_helper import generate_ast_from_code, has_import_like


def test_ast_imports():
    tree = generate_ast_from_code(
        """
import pymongo
import ssl

client = pymongo.MongoClient()
    """
    )
    assert has_import_like("pymongo", tree)

    tree = generate_ast_from_code(
        """
import pymongo
import ssl

client = pymongo.MongoClient('example.com', ssl=False, ssl_cert_reqs=ssl.CERT_NONE)
    """
    )
    assert has_import_like("pymongo", tree)

    tree = generate_ast_from_code(
        """
import pymongo
import ssl

client = pymongo.MongoClient('mongodb://example.com/?ssl=true')
    """
    )
    assert has_import_like("pymongo", tree)


def test_ast_imports_from():
    tree = generate_ast_from_code(
        """
from pymongo import MongoClient
import ssl

client = MongoClient('mongodb://example.com/?ssl=true')
    """
    )
    assert has_import_like("pymongo", tree)
