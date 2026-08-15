import uuid
import os
from bson import ObjectId
import gridfs
from pymongo import MongoClient
from django.conf import settings


def _get_gridfs():
    client = MongoClient(settings.MONGODB_URI)
    db = client.get_default_database()
    return gridfs.GridFS(db, collection='uploads')


def upload_to_gridfs(file_obj, original_name: str, mimetype: str):
    fs = _get_gridfs()
    ext = os.path.splitext(original_name)[1]
    filename = str(uuid.uuid4()) + ext
    file_id = fs.put(
        file_obj,
        filename=filename,
        content_type=mimetype,
        metadata={'originalname': original_name}
    )
    return file_id


def download_from_gridfs(gridfs_id):
    fs = _get_gridfs()
    return fs.get(ObjectId(str(gridfs_id)))


def delete_from_gridfs(gridfs_id):
    fs = _get_gridfs()
    fs.delete(ObjectId(str(gridfs_id)))
