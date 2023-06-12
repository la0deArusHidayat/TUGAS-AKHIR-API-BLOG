from flask import Flask, request, render_template, make_response, jsonify, redirect, url_for
from flask_restful import Resource, Api
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from functools import wraps
import jwt
import os
import datetime

app = Flask(__name__)
api = Api(app)

CORS(app)

# Konfigurasi database
filename = os.path.dirname(os.path.abspath(__file__))
database = 'sqlite:///' + os.path.join(filename, 'db.sqlite')
app.config['SQLALCHEMY_DATABASE_URI'] = database
db = SQLAlchemy(app)

# Konfigurasi secret key
app.config['SECRET_KEY'] = "inirahasianegara"

# Model Auth
class AuthModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(50))
    password = db.Column(db.String(100))

class BlogModel(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    judul = db.Column(db.String(100))
    konten = db.Column(db.Text)
    penulis = db.Column(db.String(50))

# Buat tabel dalam database
with app.app_context():
    db.create_all()

# membuat decorator
def butuh_token(f):
    @wraps(f)
    def decorator(*args, **kwargs):
        token = request.args.get('datatoken')  # Mengambil token dari URL parameter
        if not token:
            return make_response(jsonify({"msg": "Token nggak ada bro!", "popup": "error"}), 401)
        try:
            jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        except jwt.exceptions.InvalidSignatureError:
            return make_response(jsonify({"msg": "Token nggak bener bro / invalid", "popup": "error"}), 401)
        except jwt.exceptions.ExpiredSignatureError:
            return make_response(jsonify({"msg": "Token sudah kadaluarsa", "popup": "error"}), 401)
        except jwt.exceptions.DecodeError:
            return make_response(jsonify({"msg": "Token format tidak valid", "popup": "error"}), 401)
        return f(*args, **kwargs)
    return decorator


# membuat routing endpoint 
# routing authentikasi 
class RegisterUser(Resource):
    # posting data dari front end untuk disimpan ke dalam database
    def post(self):
        dataUsername = request.form.get('username')
        dataPassword = request.form.get('password')

        # cek apakah username & password ada
        if dataUsername and dataPassword:
            # tulis data authentikasi ke db.sqlite
            dataModel = AuthModel(username=dataUsername, password=dataPassword)
            db.session.add(dataModel)
            db.session.commit()
            return make_response(jsonify({"msg":"Registrasi berhasil", "popup":"success"}), 200)
        return jsonify({"msg":"Username / password tidak boleh kosong", "popup":"error"})


# routing untuk authentikasi: login
# routing untuk authentikasi: login
class LoginUser(Resource):
    def post(self):
        dataUsername = request.form.get('username')
        dataPassword = request.form.get('password')

        # query matching kecocokan data
        # iterasi authModel

        # cek username dan password
        queryUsername = [data.username for data in AuthModel.query.all()]
        queryPassword = [data.password for data in AuthModel.query.all()]
        if dataUsername in queryUsername and dataPassword in queryPassword:
            # klo login sukses
            # generate token authentikasi untuk ditampilkan
            token = jwt.encode({
                'username': dataUsername,
                'exp': datetime.datetime.utcnow() + datetime.timedelta(seconds=7200)
            }, app.config['SECRET_KEY'])
            return make_response(jsonify({"msg":"Login Sukses", "token":token}), 200)
        else:
            return jsonify({"msg": "Username atau password salah", "popup":"error"})



class TambahArtikel(Resource):
    @butuh_token
    def post(self):
        # Retrieve the token from the form data
        datatoken = request.form.get('datatoken')

        # Retrieve article data from the form
        dataJudul = request.form.get('judul')
        dataKonten = request.form.get('konten')
        dataPenulis = request.form.get('penulis')

        # Create a new article and add it to the database
        data = BlogModel(judul=dataJudul, konten=dataKonten, penulis=dataPenulis)
        db.session.add(data)
        db.session.commit()

        return {
            "msg": "Artikel berhasil ditambahkan!",
            "token": datatoken  # Include the token in the response
        }, 200



    # melihat semua artikel yang telah dibuat/publish
    # akan diproteksi
    @butuh_token
    def get(self):
        # query data dari database blogmodel (query semua datanya)
        dataQuery = BlogModel.query.all()
        # lakukan looping datanya ==> list comprehension 
        # list di dalamnya dict
        output = [
            {
                "id":data.id,
                "judul":data.judul,
                "konten":data.konten,
                "penulis":data.penulis
            } for data in dataQuery
        ] 

        return make_response(jsonify(output), 200)

# routing untuk update dan delete blog
class UpdateDataById(Resource):
    # untuk mengupdate data artikel
    @butuh_token
    def put(self, id):
        token = request.args.get('datatoken')  # Mengambil token dari URL parameter
        data = jwt.decode(token, app.config['SECRET_KEY'], algorithms=["HS256"])
        judul = request.form.get('judul')
        konten = request.form.get('konten')
        penulis = data['username']

        # memperbarui judul dan konten artikel berdasarkan id
        BlogModel.query.filter_by(id=id).update({BlogModel.judul: judul, BlogModel.konten: konten, BlogModel.penulis: penulis})
        db.session.commit()
        return make_response(jsonify({"msg": "Artikel berhasil diperbarui", "popup": "success"}), 200)

    # untuk menghapus data artikel
    @butuh_token
    def delete(self, id):
        # menghapus artikel berdasarkan id
        BlogModel.query.filter_by(id=id).delete()
        db.session.commit()
        return make_response(jsonify({"msg": "Artikel berhasil dihapus", "popup": "success"}), 200)


# route ke halaman index
@app.route('/')
def index():
    return render_template('index.html')


# route ke halaman login
@app.route('/login')
def login():
    return render_template('login.html')


# route ke halaman register
@app.route('/register')
def register():
    return render_template('register.html')



# inisiasi resource api 
api.add_resource(RegisterUser, "/api/register", methods=["POST"])
api.add_resource(LoginUser, "/api/login", methods=["POST"])
api.add_resource(TambahArtikel, "/api/blog", methods=["GET", "POST"])
api.add_resource(UpdateDataById, "/api/blog/<id>", methods=["PUT", "DELETE", "GET"])

if __name__ == '__main__':
    app.run(debug=True)

