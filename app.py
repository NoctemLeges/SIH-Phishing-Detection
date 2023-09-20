from flask import Flask, render_template, request,redirect,url_for

app = Flask("_name__")

stored_strings = []
@app.route("/",methods = ['GET','POST'])
def index():
    if request.method == 'POST':
        input_string = request.form['url']
        stored_strings.append(input_string)
        return redirect(url_for('index'))
    return render_template('index.html',stored_strings=stored_strings)

if __name__ == "__main__":
    app.run(debug = True)