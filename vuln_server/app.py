from flask import Flask, request, jsonify
import graphene
from graphene import ObjectType, String, Schema, Field

# Mock Database
USERS = {
    "1": {"id": "1", "username": "admin", "secret": "s3cr3t_k3y"},
    "2": {"id": "2", "username": "guest", "secret": "guest_pass"},
}

class User(ObjectType):
    id = String()
    username = String()
    secret = String()

class Query(ObjectType):
    user = Field(User, id=String(required=True))
    echo = String(text=String(required=True))
    debug = String()
    error = String()

    def resolve_user(self, info, id):
        print(f"Resolving user with id: {id}")
        # MOCKED SQL INJECTION VULNERABILITY
        if "'" in id or "OR" in id:
            # Simulate SQL error leak
            raise Exception("SQL Syntax Error: SELECT * FROM users WHERE id = '" + id + "'")
        
        # IDOR / Normal lookup
        return USERS.get(id)

    def resolve_echo(self, info, text):
        # MOCKED XSS VULNERABILITY (Reflected)
        # In a real app, this might be rendered in a frontend
        return text

    def resolve_debug(self, info):
        # MOCKED DEBUG FIELD
        return "Debug mode enabled. System info: Linux 5.4.0..."

    def resolve_error(self, info):
        # MOCKED STACK TRACE
        raise Exception("Traceback (most recent call last):\n  File 'app.py', line 42, in resolve_error")

schema = Schema(query=Query)

app = Flask(__name__)

@app.route('/graphql', methods=['POST'])
def graphql_server():
    data = request.get_json()
    result = schema.execute(
        data.get('query'), 
        variables=data.get('variables')
    )
    
    response = {'data': result.data}
    if result.errors:
        response['errors'] = [{'message': str(e)} for e in result.errors]
        
    return jsonify(response)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
