/*
Alize is a free, open tool for speaker recognition

Alize is a development project initiated by the ELISA consortium
  [www.lia.univ-avignon.fr/heberges/ALIZE/ELISA] and funded by the
  French Research Ministry in the framework of the
  TECHNOLANGUE program [www.technolangue.net]
  [www.technolangue.net]

The Alize project team wants to highlight the limits of voice 
  authentication in a forensic context.
  The following paper proposes a good overview of this point:
  [Bonastre J.F., Bimbot F., Boe L.J., Campbell J.P., Douglas D.A., 
  Magrin-chagnolleau I., Person  Authentification by Voice: A Need of 
  Caution, Eurospeech 2003, Genova]
  The conclusion of the paper of the paper is proposed bellow:
  [Currently, it is not possible to completely determine whether the 
  similarity between two recordings is due to the speaker or to other 
  factors, especially when: (a) the speaker does not cooperate, (b) there 
  is no control over recording equipment, (c) recording conditions are not 
  known, (d) one does not know whether the voice was disguised and, to a 
  lesser extent, (e) the linguistic content of the message is not 
  controlled. Caution and judgment must be exercised when applying speaker 
  recognition techniques, whether human or automatic, to account for these 
  uncontrolled factors. Under more constrained or calibrated situations, 
  or as an aid for investigative purposes, judicious application of these 
  techniques may be suitable, provided they are not considered as infallible.
  At the present time, there is no scientific process that enables one to 
  uniquely characterize a person=92s voice or to identify with absolute 
  certainty an individual from his or her voice.]
  Contact Jean-Francois Bonastre for more information about the licence or
  the use of Alize

Copyright (C) 2003-2005
  Laboratoire d'informatique d'Avignon [www.lia.univ-avignon.fr]
  Frederic Wils [frederic.wils@lia.univ-avignon.fr]
  Jean-Francois Bonastre [jean-francois.bonastre@lia.univ-avignon.fr]
      
This file is part of Alize.

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.

This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.

You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
*/

#if !defined(ALIZE_FrameAccGD_h)
#define ALIZE_FrameAccGD_h

#include "FrameAcc.h"
#include "RealVector.h"

namespace alize
{
  /// Class used to compute mean and covariance (DIAG) of a set of 
  /// features
  ///
  /// @author Frederic Wils  frederic.wils@lia.univ-avignon.fr
  /// @version 1.0
  /// @date 2003
  ///
  class FrameAccGD : public FrameAcc
  {
  friend class TestFrameAccGD;
  public :
    explicit FrameAccGD();
    static FrameAccGD& create();
    const FrameAccGD& operator=(const FrameAccGD&);
    FrameAccGD(const FrameAccGD&);
    virtual ~FrameAccGD();
    virtual void accumulate(const Feature& f);

    /// Delete an accumulated feature
    /// @param f the feature to delete
    /// LIUM Modification
    ///
    virtual void deaccumulate(const Feature& f);

    /// Returns the accumulated square parameters vector
    /// @return the accumulated square parameters vector
    ///
    const DoubleVector& getxAccVect() const;

    /// Returns the covariance vector
    /// @return the covariance vector
    ///
    const DoubleVector& getCovVect();

    /// Returns the standard deviation vector
    /// @return the standard deviation vector
    ///
    const DoubleVector& getStdVect();

    /// Add the values from another FrameAcc - LIUM Modification
    /// @param f the frame acc
    ///
    void add(const FrameAccGD& f);

    virtual String getClassName() const;

  private:
    DoubleVector _xaccVect;
    DoubleVector _covVect;
    DoubleVector _stdVect;
    virtual void computeAll();
    void copy(const FrameAccGD&);
    bool operator==(const FrameAccGD&) const;/*!Not implemented*/
    bool operator!=(const FrameAccGD&) const;/*!Not implemented*/
  };

} // end namespace alize

#endif // !defined(ALIZE_FrameAccGD_h)

