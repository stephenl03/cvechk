from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired


def os_choices():
    oslist = [("RHEL_6", "RHEL 6"),
              ("RHEL_7", "RHEL 7")]
    return oslist


class CVEInputForm(FlaskForm):
    uos = SelectField(coerce=str, choices=os_choices())
    uinputtext = TextAreaField(validators=[DataRequired()])
    submit_button = SubmitField('Submit')


class ResultsForm(FlaskForm):
    back_button = SubmitField('Back')
