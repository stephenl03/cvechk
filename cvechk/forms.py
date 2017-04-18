from flask_wtf import FlaskForm
from wtforms import SelectField, SubmitField, TextAreaField
from wtforms.validators import DataRequired, Length


def os_choices():
    oslist = [("EL_6", "EL 6"),
              ("EL_7", "EL 7")]
    return oslist


class CVEInputForm(FlaskForm):
    uos = SelectField(coerce=str, choices=os_choices())
    uinputtext = TextAreaField(validators=[DataRequired(), Length(min=3)])
    submit_button = SubmitField('Submit')


class ResultsForm(FlaskForm):
    back_button = SubmitField('Back')
